package ds389

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

const aciOwnerPrefix = "labldap:"

var aciNameRe = regexp.MustCompile(`(?i)acl\s+"([^"]+)"`)

func (e Engine) ReconcileACIs(ctx context.Context, req bootstrap.ACIRequest) (bootstrap.ACIResult, error) {
	if req.DialTimeout <= 0 {
		req.DialTimeout = 5 * time.Second
	}
	dial := e.TreeDial
	if dial == nil {
		dial = defaultTreeDial
	}
	conn, err := dial(ctx, req.TreeRequest)
	if err != nil {
		return bootstrap.ACIResult{}, bootstrap.PhaseError("aci", "server_reject", "could not bind as Directory Manager to apply ACIs").Wrap(err)
	}
	defer conn.Close()

	var res bootstrap.ACIResult
	byTarget := groupACIs(req.ACIs)
	targets := make([]string, 0, len(byTarget))
	seen := map[string]struct{}{}
	for _, a := range req.ACIs {
		if _, ok := seen[a.Target]; ok {
			continue
		}
		seen[a.Target] = struct{}{}
		targets = append(targets, a.Target)
	}
	for _, target := range targets {
		want := byTarget[target]
		if err := e.reconcileTargetACIs(conn, req, target, want, &res); err != nil {
			return res, err
		}
	}
	return res, nil
}

func (e Engine) reconcileTargetACIs(conn treeConn, req bootstrap.ACIRequest, target string, want []config.NamedACI, res *bootstrap.ACIResult) error {
	live, err := readACIs(conn, target)
	if err != nil {
		return bootstrap.PhaseError("aci", "server_reject", "could not read ACIs").Wrap(err)
	}
	gotOwned := ownedByName(live)
	wantByID := map[string]config.NamedACI{}
	for _, a := range want {
		wantByID[a.ID] = a
	}
	for _, a := range want {
		if err := requireOwnedName(a); err != nil {
			return err
		}
	}
	if req.Write {
		for id, text := range gotOwned {
			if _, keep := wantByID[id]; keep {
				continue
			}
			if err := modifyACI(conn, target, ldap.Change{Operation: ldap.DeleteAttribute, Modification: ldap.PartialAttribute{Type: "aci", Vals: []string{text}}}); err != nil {
				return rejectACI(id, "could not remove leftover named ACI").Wrap(err)
			}
		}
		live, err = readACIs(conn, target)
		if err != nil {
			return bootstrap.PhaseError("aci", "server_reject", "could not read ACIs").Wrap(err)
		}
		gotOwned = ownedByName(live)
		for _, a := range want {
			if existing, ok := gotOwned[a.ID]; ok {
				if canonACI(existing) == canonACI(a.Text) {
					res.Matched = append(res.Matched, a.ID)
					continue
				}
				if err := replaceACI(conn, target, existing, a.Text); err != nil {
					return rejectACI(a.ID, "directory rejected ACL "+a.ID).Wrap(err)
				}
				res.Applied = append(res.Applied, a.ID)
				continue
			}
			if err := modifyACI(conn, target, ldap.Change{Operation: ldap.AddAttribute, Modification: ldap.PartialAttribute{Type: "aci", Vals: []string{a.Text}}}); err != nil {
				if isTypeOrValueExists(err) {
					res.Matched = append(res.Matched, a.ID)
					continue
				}
				return rejectACI(a.ID, "directory rejected ACL "+a.ID).Wrap(err)
			}
			res.Applied = append(res.Applied, a.ID)
		}
		live, err = readACIs(conn, target)
		if err != nil {
			return bootstrap.PhaseError("aci", "server_reject", "could not read ACIs after apply").Wrap(err)
		}
	}
	return compareNamed(live, want)
}

func compareNamed(live []string, want []config.NamedACI) error {
	gotOwned := ownedByName(live)
	for _, a := range want {
		existing, ok := gotOwned[a.ID]
		if !ok {
			return rejectACI(a.ID, "named ACI "+a.ID+" is not present")
		}
		if canonACI(existing) != canonACI(a.Text) {
			return rejectACI(a.ID, "named ACI "+a.ID+" does not match the plan")
		}
	}
	return nil
}

func readACIs(conn treeConn, dn string) ([]string, error) {
	sr, err := conn.Search(&ldap.SearchRequest{
		BaseDN:     dn,
		Scope:      ldap.ScopeBaseObject,
		Filter:     "(objectClass=*)",
		Attributes: []string{"aci"},
	})
	if err != nil {
		return nil, err
	}
	if len(sr.Entries) == 0 {
		return nil, nil
	}
	return sr.Entries[0].GetAttributeValues("aci"), nil
}

func ownedByName(values []string) map[string]string {
	out := map[string]string{}
	for _, v := range values {
		id, ok := aciName(v)
		if !ok || !strings.HasPrefix(id, aciOwnerPrefix) {
			continue
		}
		out[id] = v
	}
	return out
}

func aciName(text string) (string, bool) {
	m := aciNameRe.FindStringSubmatch(text)
	if len(m) < 2 {
		return "", false
	}
	return m[1], true
}

func canonACI(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func groupACIs(acis []config.NamedACI) map[string][]config.NamedACI {
	out := map[string][]config.NamedACI{}
	for _, a := range acis {
		if a.Target == "" || a.ID == "" || a.Text == "" {
			continue
		}
		out[a.Target] = append(out[a.Target], a)
	}
	return out
}

func replaceACI(conn treeConn, dn, oldText, newText string) error {
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Delete("aci", []string{oldText})
	mod.Add("aci", []string{newText})
	return conn.Modify(mod)
}

func modifyACI(conn treeConn, dn string, ch ldap.Change) error {
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Changes = append(mod.Changes, ch)
	return conn.Modify(mod)
}

func requireOwnedName(a config.NamedACI) error {
	name, ok := aciName(a.Text)
	if !ok || name != a.ID || !strings.HasPrefix(a.ID, aciOwnerPrefix) {
		return rejectACI(a.ID, "named ACI "+a.ID+" text does not carry a matching labldap: ACL name")
	}
	return nil
}

func rejectACI(id, public string) *apperr.Error {
	if id != "" && !strings.Contains(public, id) {
		public = public + " (" + id + ")"
	}
	return bootstrap.PhaseError("aci", "server_reject", public)
}

func isTypeOrValueExists(err error) bool {
	var le *ldap.Error
	return errors.As(err, &le) && le.ResultCode == ldap.LDAPResultAttributeOrValueExists
}
