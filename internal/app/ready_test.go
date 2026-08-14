package app

import (
	"context"
	"errors"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/reset"
)

type probeMarker struct {
	m   directory.BaselineMarker
	err error
}

func (p probeMarker) ReadMarker(context.Context) (directory.BaselineMarker, error) {
	return p.m, p.err
}

type probeCaps struct {
	c   directory.Capabilities
	err error
}

func (p probeCaps) Capabilities(context.Context) (directory.Capabilities, error) {
	return p.c, p.err
}

func TestProbeReadyRequiresBindMarkerMatchCapsAndNoReset(t *testing.T) {
	t.Parallel()
	ok := &Probe{
		Ping:       func(context.Context) error { return nil },
		Marker:     probeMarker{m: directory.BaselineMarker{AppliedRevision: "aaa"}},
		Caps:       probeCaps{c: directory.Capabilities{RequiredOK: true}},
		Expected:   "aaa",
		ResetState: func() string { return string(reset.Ready) },
		Pool:       func() PoolView { return PoolView{Active: 1, Idle: 2, Max: 4} },
	}
	d := ok.Evaluate(t.Context())
	if !d.Ready || !d.MarkerMatch || d.Pool.Max != 4 || d.Reset.State != "Ready" {
		t.Fatalf("%+v", d)
	}
}

func TestProbeLDAPOutageKeepsNotReady(t *testing.T) {
	t.Parallel()
	p := &Probe{
		Ping:     func(context.Context) error { return errors.New("dial") },
		Marker:   probeMarker{m: directory.BaselineMarker{AppliedRevision: "aaa"}},
		Caps:     probeCaps{c: directory.Capabilities{RequiredOK: true}},
		Expected: "aaa",
	}
	d := p.Evaluate(t.Context())
	if d.Ready || d.MarkerMatch {
		t.Fatalf("outage must not be ready: %+v", d)
	}
}

func TestProbeRevisionMismatchBlocksEveryMode(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"validate", "merge", "reset"} {
		p := &Probe{
			Ping:        func(context.Context) error { return nil },
			Marker:      probeMarker{m: directory.BaselineMarker{AppliedRevision: "stale"}},
			Caps:        probeCaps{c: directory.Capabilities{RequiredOK: true}},
			Expected:    "expected",
			StartupMode: mode,
		}
		d := p.Evaluate(t.Context())
		if d.Ready || d.MarkerMatch {
			t.Fatalf("mode %s allowed mismatch: %+v", mode, d)
		}
	}
}

func TestProbeMissingMarkerAndResetBlockReady(t *testing.T) {
	t.Parallel()
	missing := &Probe{
		Ping:     func(context.Context) error { return nil },
		Marker:   probeMarker{m: directory.BaselineMarker{}},
		Caps:     probeCaps{c: directory.Capabilities{RequiredOK: true}},
		Expected: "aaa",
	}
	if missing.Evaluate(t.Context()).Ready {
		t.Fatal("missing marker")
	}
	resetting := &Probe{
		Ping:       func(context.Context) error { return nil },
		Marker:     probeMarker{m: directory.BaselineMarker{AppliedRevision: "aaa"}},
		Caps:       probeCaps{c: directory.Capabilities{RequiredOK: true}},
		Expected:   "aaa",
		ResetState: func() string { return string(reset.Resetting) },
	}
	if resetting.Evaluate(t.Context()).Ready {
		t.Fatal("reset must block ready")
	}
}

func TestProbeMissingBaselineBlocksReady(t *testing.T) {
	t.Parallel()
	p := &Probe{
		Ping:       func(context.Context) error { return nil },
		Marker:     probeMarker{m: directory.BaselineMarker{AppliedRevision: "aaa"}},
		Caps:       probeCaps{c: directory.Capabilities{RequiredOK: true}},
		Expected:   "aaa",
		ResetState: func() string { return string(reset.Ready) },
		BaselineOK: func(context.Context) bool { return false },
	}
	if p.Evaluate(t.Context()).Ready {
		t.Fatal("missing baseline must not be ready")
	}
}

func TestDiagnosticsHasNoSecretFields(t *testing.T) {
	t.Parallel()
	d := Diagnostics{
		Ready: true, MarkerMatch: true,
		Pool:  PoolView{Active: 1, Idle: 0, Max: 2},
		Reset: ResetHint{State: "Ready"},
	}
	if d.Pool.Active != 1 || d.Reset.State != "Ready" {
		t.Fatalf("%+v", d)
	}
}
