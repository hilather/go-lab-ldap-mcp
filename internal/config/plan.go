package config

import (
	"sort"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1"
)

type EnginePlan struct {
	Engine         string           `json:"engine"`
	Suffix         string           `json:"suffix"`
	BackendName    string           `json:"backendName"`
	PasswordPolicy NormalizedPolicy `json:"passwordPolicy"`
	Plugins        []string         `json:"plugins"`
}

type DataOp struct {
	Kind string `json:"kind"` // user|group|container|account|marker
	ID   string `json:"id"`
	DN   string `json:"dn"`
}

type DataPlan struct {
	Creates        []DataOp   `json:"creates"`
	Deletes        []DataOp   `json:"deletes"`
	Preserve       []string   `json:"preserve"`
	ServiceAccount string     `json:"serviceAccount"`
	Marker         string     `json:"marker"`
	Users          []string   `json:"users"`
	Groups         []string   `json:"groups"`
	ACIs           []NamedACI `json:"acis"`
}

func buildEnginePlan(n *Normalized) EnginePlan {
	return EnginePlan{
		Engine:         n.Engine,
		Suffix:         n.Suffix.String(),
		BackendName:    "userroot",
		PasswordPolicy: n.Policy,
		Plugins:        []string{"memberof", "referint", "account-disable"},
	}
}

// wiredEngines lists the directory engines this build of labldap and
// labldap-bootstrap can actually run. T-123 shipped the selection surface
// with 389ds only; T-146 wired native (labldapd + the native read-back
// bootstrap reconcilers in internal/directory/native, ADR-0009).
var wiredEngines = []string{v1alpha1.Engine389DS, v1alpha1.EngineNative}

// RequireAvailableEngine fails closed when the compiled engine is not wired
// into this build. Call it after a successful Compile and before any
// directory dial so an unwired engine never reaches the network
// half-configured. The schema enum already rejects unknown engines at
// compile time; this is the defense-in-depth gate behind it.
func RequireAvailableEngine(engine string) error {
	if contains(wiredEngines, engine) {
		return nil
	}
	return apperr.New(apperr.CodeConfiguration, "directory engine is not available in this build").
		WithField(apperr.Field{
			Path: "spec.directory.engine",
			Code: "engine_not_available",
			Message: "engine " + engine + " is not wired in this build; " +
				"use engine: " + v1alpha1.Engine389DS + " or engine: " + v1alpha1.EngineNative,
		})
}

func buildDataPlan(n *Normalized, acis []NamedACI) DataPlan {
	markerDN := "cn=labldap-baseline," + n.Suffix.String()
	creates := []DataOp{
		{Kind: "container", ID: "suffix", DN: n.Suffix.String()},
		{Kind: "container", ID: "people", DN: n.PeopleDN.String()},
		{Kind: "container", ID: "groups", DN: n.GroupsDN.String()},
		{Kind: "account", ID: n.Runtime.ID, DN: n.Runtime.DN},
	}
	var users, groups []string
	for _, u := range n.Users {
		creates = append(creates, DataOp{Kind: "user", ID: u.ID, DN: u.DN})
		users = append(users, u.DN)
	}
	for _, g := range n.Groups {
		creates = append(creates, DataOp{Kind: "group", ID: g.ID, DN: g.DN})
		groups = append(groups, g.DN)
	}
	creates = append(creates, DataOp{Kind: "marker", ID: "baseline", DN: markerDN})
	deletes := make([]DataOp, len(creates))
	for i, op := range creates {
		deletes[len(creates)-1-i] = op
	}
	preserve := []string{n.Runtime.DN, n.PeopleDN.String(), n.GroupsDN.String(), markerDN}
	sort.Strings(preserve)
	return DataPlan{
		Creates:        creates,
		Deletes:        deletes,
		Preserve:       preserve,
		ServiceAccount: n.Runtime.DN,
		Marker:         markerDN,
		Users:          users,
		Groups:         groups,
		ACIs:           acis,
	}
}
