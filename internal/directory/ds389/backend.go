package ds389

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// Engine reconciles 389 DS engine settings via dsconf and LDAP probes.
type Engine struct {
	Runner      Runner
	Dial        DialFunc
	TreeDial    TreeDialFunc
	RuntimeBind func(ctx context.Context, req bootstrap.TreeRequest) error
	// RuntimeDial, if set, opens the runtime LDAP session used by verify probes.
	RuntimeDial TreeDialFunc
	SeedBind    func(ctx context.Context, req bootstrap.TreeRequest, dn, password string) error
	// UserBind, if set, replaces application bind probes (T-037).
	UserBind func(ctx context.Context, req bootstrap.TreeRequest, dn, password string) error
	// SeedPasswordReplace, if set, replaces the post-add password modify so tests can inject password_set.
	SeedPasswordReplace func(dn, password string) error
}

type listedBackend struct {
	Name   string
	Suffix string
}

func (e Engine) Reconcile(ctx context.Context, req bootstrap.BackendRequest) (bootstrap.BackendResult, error) {
	wantName := req.Name
	if wantName == "" {
		wantName = "userroot"
	}
	wantDN, err := config.ParseDN(req.Suffix)
	if err != nil {
		return bootstrap.BackendResult{}, bootstrap.PhaseError("backend", "conflict", "configured suffix is not a valid DN")
	}
	listed, err := e.list(ctx, req)
	if err != nil {
		return bootstrap.BackendResult{}, bootstrap.PhaseError("backend", "create_failed", "could not list backends").Wrap(err)
	}
	var nameHit, suffixHit *listedBackend
	for i := range listed {
		b := &listed[i]
		if strings.EqualFold(b.Name, wantName) {
			nameHit = b
		}
		got, perr := config.ParseDN(b.Suffix)
		if perr == nil && got.Equal(wantDN) {
			suffixHit = b
		}
	}
	if nameHit != nil && suffixHit != nil && nameHit.Name == suffixHit.Name {
		return bootstrap.BackendResult{Action: "matched", Name: nameHit.Name, Suffix: nameHit.Suffix}, nil
	}
	if nameHit != nil || suffixHit != nil {
		return bootstrap.BackendResult{}, bootstrap.PhaseError("backend", "conflict", "existing backend name or suffix does not match the plan")
	}
	if !req.Write {
		return bootstrap.BackendResult{}, bootstrap.PhaseError("backend", "missing", "planned backend is not present")
	}
	_, err = e.Runner.JSON(ctx, req.PasswordFile, req.Instance, []string{
		"backend", "create",
		"--suffix", wantDN.String(),
		"--be-name", wantName,
		"--create-suffix",
	})
	if err != nil {
		code := "create_failed"
		if isMappingConflict(err.Error()) {
			code = "conflict"
		}
		return bootstrap.BackendResult{}, bootstrap.PhaseError("backend", code, "backend create failed").Wrap(err)
	}
	return bootstrap.BackendResult{Action: "created", Name: wantName, Suffix: wantDN.String()}, nil
}

func (e Engine) list(ctx context.Context, req bootstrap.BackendRequest) ([]listedBackend, error) {
	raw, err := e.Runner.JSON(ctx, req.PasswordFile, req.Instance, []string{"backend", "suffix", "list"})
	if err != nil {
		return nil, err
	}
	return parseSuffixList(raw)
}

func parseSuffixList(raw []byte) ([]listedBackend, error) {
	var doc struct {
		Items []string `json:"items"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	out := make([]listedBackend, 0, len(doc.Items))
	for _, item := range doc.Items {
		name, suffix, ok := splitListItem(item)
		if !ok {
			continue
		}
		out = append(out, listedBackend{Name: name, Suffix: suffix})
	}
	return out, nil
}

// "dc=example,dc=test (userroot)"
func splitListItem(item string) (name, suffix string, ok bool) {
	item = strings.TrimSpace(item)
	i := strings.LastIndex(item, " (")
	if i < 1 || !strings.HasSuffix(item, ")") {
		return "", "", false
	}
	suffix = strings.TrimSpace(item[:i])
	name = strings.TrimSpace(item[i+2 : len(item)-1])
	if suffix == "" || name == "" {
		return "", "", false
	}
	return name, suffix, true
}

func isMappingConflict(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "mapping tree") || strings.Contains(m, "already exist")
}
