package bootstrap

import (
	"context"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// Capabilities is the T-044 measured engine report. Secret-free.
type Capabilities struct {
	EngineVendor   string   `json:"engineVendor"`
	EngineVersion  string   `json:"engineVersion"`
	AdapterVersion string   `json:"adapterVersion"`
	Transports     []string `json:"transports"`
	Plugins        []string `json:"plugins"`
	PasswordScheme string   `json:"passwordScheme"`
	Controls       []string `json:"controls"`
	RequiredOK     bool     `json:"requiredOK"`
}

// CapabilityRequest is the inspect input for Engine.Capabilities.
type CapabilityRequest struct {
	TreeRequest
	PasswordFile       string
	Instance           string
	RequiredPlugins    []string
	RequiredTransports []string
	RequiredScheme     string
	Phase              string
}

// CapabilityInspector measures Root DSE, plugins, transports, and scheme.
type CapabilityInspector interface {
	Capabilities(ctx context.Context, req CapabilityRequest) (Capabilities, error)
}

// DriftRequest is a read-only inventory compare. Exit policy lives in
// bootstrap.Run: validate fails on Differ, apply leftover never fails.
type DriftRequest struct {
	TreeRequest
	Users             []config.NormalizedUser
	Groups            []config.NormalizedGroup
	ACIs              []config.NamedACI
	MarkerDN          string
	DirectoryRevision string
	Preserve          []string
	// CompareMarker includes marker revision mismatch in Differ.
	// Validate sets this. Apply leftover reports keep the revision
	// fields but do not treat a soon-to-be-written marker as drift.
	CompareMarker bool
}

// DriftReport is secret-free JSON attached to Summary.drift.
type DriftReport struct {
	ExpectedUsers    []string `json:"expectedUsers"`
	LiveUsers        []string `json:"liveUsers"`
	ExtraUsers       []string `json:"extraUsers,omitempty"`
	MissingUsers     []string `json:"missingUsers,omitempty"`
	ExpectedGroups   []string `json:"expectedGroups"`
	LiveGroups       []string `json:"liveGroups"`
	ExtraGroups      []string `json:"extraGroups,omitempty"`
	MissingGroups    []string `json:"missingGroups,omitempty"`
	ExpectedACIs     []string `json:"expectedACIs"`
	LiveACIs         []string `json:"liveACIs"`
	ExtraACIs        []string `json:"extraACIs,omitempty"`
	MissingACIs      []string `json:"missingACIs,omitempty"`
	MarkerRevision   string   `json:"markerRevision,omitempty"`
	ExpectedRevision string   `json:"expectedRevision"`
	Differ           bool     `json:"differ"`
}

// DriftInspector inventories the suffix against the compiled plan.
type DriftInspector interface {
	Inspect(ctx context.Context, req DriftRequest) (DriftReport, error)
}
