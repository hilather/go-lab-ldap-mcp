package bootstrap

import "context"

// Marker is the protected baseline entry under the managed suffix.
// Values are revisions, apply version, and timestamp only — never secrets.
type Marker struct {
	DN               string `json:"dn"`
	AppliedRevision  string `json:"appliedRevision"`
	ExpectedRevision string `json:"expectedRevision"`
	ApplyVersion     string `json:"applyVersion"`
	AppliedAt        string `json:"appliedAt"`
	Encoding         string `json:"encoding,omitempty"`
}

// MarkerRequest is the bootstrap-only (DM) marker read/write input.
type MarkerRequest struct {
	TreeRequest
	DN               string
	AppliedRevision  string
	ExpectedRevision string
	ApplyVersion     string
	AppliedAt        string
}

// MarkerWriter reads and writes cn=labldap-baseline,<suffix>.
// WriteMarker is bootstrap-only; control and soft reset must only Read.
type MarkerWriter interface {
	ReadMarker(ctx context.Context, req MarkerRequest) (Marker, error)
	WriteMarker(ctx context.Context, req MarkerRequest) error
}
