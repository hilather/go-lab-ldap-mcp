package app

import (
	"context"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// Query owns search, bind-test, schema, capability, and baseline reads.
type Query struct {
	search   directory.SearchRepository
	bind     directory.BindTester
	schema   directory.SchemaRepository
	caps     directory.CapabilityInspector
	marker   directory.MarkerReader
	expected string
	control  string
	hooks    hooks
}

func (s *Query) Search(ctx context.Context, p Principal, q directory.SearchQuery) (directory.SearchPage, error) {
	if err := s.hooks.authorize(p, OpSearch); err != nil {
		return directory.SearchPage{}, err
	}
	page, err := s.search.Search(ctx, q)
	if err != nil {
		return directory.SearchPage{}, err
	}
	page.Entries = redactEntries(page.Entries)
	return page, nil
}

func (s *Query) BindTest(ctx context.Context, p Principal, identity string, password observability.Secret, transport directory.Transport) (directory.BindTestResult, error) {
	if err := s.hooks.authorize(p, OpBindTest); err != nil {
		return directory.BindTestResult{}, err
	}
	if err := s.hooks.rateLimit(ctx, "bind:"+p.ID); err != nil {
		return directory.BindTestResult{}, err
	}
	res, err := s.bind.BindTest(ctx, identity, password, transport)
	if err != nil && isUnavailable(err) {
		return directory.BindTestResult{Outcome: directory.BindOutcomeUnavailable}, err
	}
	return res, err
}

func (s *Query) RootDSE(ctx context.Context, p Principal) (directory.RootDSE, error) {
	if err := s.hooks.authorize(p, OpSchemaRead); err != nil {
		return directory.RootDSE{}, err
	}
	return s.schema.RootDSE(ctx)
}

func (s *Query) Schema(ctx context.Context, p Principal) (directory.Schema, error) {
	if err := s.hooks.authorize(p, OpSchemaRead); err != nil {
		return directory.Schema{}, err
	}
	return s.schema.Schema(ctx)
}

func (s *Query) Capabilities(ctx context.Context, p Principal) (directory.Capabilities, error) {
	if err := s.hooks.authorize(p, OpCapabilities); err != nil {
		return directory.Capabilities{}, err
	}
	return s.caps.Capabilities(ctx)
}

func (s *Query) Baseline(ctx context.Context, p Principal) (Baseline, error) {
	if err := s.hooks.authorize(p, OpBaseline); err != nil {
		return Baseline{}, err
	}
	out := Baseline{
		ExpectedRevision: s.expected,
		ControlRevision:  s.control,
	}
	if s.marker == nil {
		out.Match = s.expected != "" && s.expected == out.AppliedRevision
		return out, nil
	}
	m, err := s.marker.ReadMarker(ctx)
	if err != nil {
		return Baseline{}, err
	}
	out.AppliedRevision = m.AppliedRevision
	out.MarkerDN = m.DN
	out.ApplyVersion = m.ApplyVersion
	out.AppliedAt = m.AppliedAt
	out.Match = s.expected != "" && s.expected == m.AppliedRevision
	return out, nil
}

func redactEntries(in []directory.SearchEntry) []directory.SearchEntry {
	if len(in) == 0 {
		return in
	}
	out := make([]directory.SearchEntry, len(in))
	for i, e := range in {
		out[i] = directory.SearchEntry{DN: e.DN, Attributes: redactAttrs(e.Attributes)}
	}
	return out
}

func redactAttrs(in []directory.AttrKV) []directory.AttrKV {
	var out []directory.AttrKV
	for _, a := range in {
		name := config.CanonicalAttr(a.Name)
		if config.ForbiddenUserAttr(a.Name) || name == "userpassword" {
			continue
		}
		if strings.HasPrefix(name, "nsslapd-rootpw") {
			continue
		}
		out = append(out, a)
	}
	return out
}
