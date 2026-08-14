package app

import (
	"context"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/reset"
)

// PoolView is secret-free pool telemetry for diagnostics (§3.8).
type PoolView struct {
	Active int `json:"active"`
	Idle   int `json:"idle"`
	Max    int `json:"max"`
}

// Diagnostics is the GET /api/v1/diagnostics body. No paths, DNs, or secrets.
type Diagnostics struct {
	Ready       bool      `json:"ready"`
	MarkerMatch bool      `json:"markerMatch"`
	Pool        PoolView  `json:"pool"`
	Reset       ResetHint `json:"reset"`
}

type ResetHint struct {
	State string `json:"state"`
}

// Probe evaluates liveness-independent readiness (T-073).
//
// Ready requires: runtime bind, marker exists, applied Directory revision
// matches expected, required capabilities, and no reset in progress.
// Revision comparison is the compiled Directory revision (user-seed digests
// omitted when softReset is false), so bootstrap and control stay aligned.
// startupMode does not relax a mismatch: validate, merge, and reset all
// block readiness when the marker is absent or stale.
//
// Degraded is live + not ready (LDAP up or down): /health stays 200 while
// /health/ready is 503 and Diagnostics.Ready is false.
type Probe struct {
	Ping        func(ctx context.Context) error
	Marker      directory.MarkerReader
	Caps        directory.CapabilityInspector
	Expected    string
	StartupMode string
	ResetState  func() string
	Pool        func() PoolView
	// BaselineOK, if set, must be true for Ready. Used after a failed
	// reset so a process restart cannot report false readiness (T-080).
	BaselineOK func(ctx context.Context) bool
}

func (p *Probe) Evaluate(ctx context.Context) Diagnostics {
	out := Diagnostics{
		Reset: ResetHint{State: string(reset.Ready)},
	}
	if p == nil {
		return out
	}
	if p.Pool != nil {
		out.Pool = p.Pool()
	}
	if p.ResetState != nil {
		if st := strings.TrimSpace(p.ResetState()); st != "" {
			out.Reset.State = st
		}
	}
	bindOK := true
	if p.Ping != nil {
		if err := p.Ping(ctx); err != nil {
			bindOK = false
		}
	} else {
		bindOK = false
	}
	markerOK := false
	match := false
	if p.Marker != nil && bindOK {
		m, err := p.Marker.ReadMarker(ctx)
		if err == nil && strings.TrimSpace(m.AppliedRevision) != "" {
			markerOK = true
			match = p.Expected != "" && p.Expected == m.AppliedRevision
		}
	}
	out.MarkerMatch = match
	capsOK := false
	if p.Caps != nil && bindOK {
		c, err := p.Caps.Capabilities(ctx)
		if err == nil {
			capsOK = c.RequiredOK
		}
	}
	resetOK := out.Reset.State == string(reset.Ready)
	baselineOK := true
	if p.BaselineOK != nil && bindOK {
		baselineOK = p.BaselineOK(ctx)
	}
	// Mode is recorded for operators; mismatch still blocks every mode.
	_ = p.StartupMode
	out.Ready = bindOK && markerOK && match && capsOK && resetOK && baselineOK
	return out
}

func (p *Probe) Ready(ctx context.Context) bool {
	return p.Evaluate(ctx).Ready
}
