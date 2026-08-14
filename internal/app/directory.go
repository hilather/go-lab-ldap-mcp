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
	sch, err := s.schema.Schema(ctx)
	if err != nil {
		return directory.Schema{}, err
	}
	return redactSchema(sch), nil
}

func (s *Query) ObjectClass(ctx context.Context, p Principal, name string) (directory.ObjectClass, error) {
	sch, err := s.Schema(ctx, p)
	if err != nil {
		return directory.ObjectClass{}, err
	}
	want := strings.TrimSpace(name)
	if want == "" {
		return directory.ObjectClass{}, directory.Error("objectclass", directory.FieldNotFound, "object class not found")
	}
	for _, oc := range sch.ObjectClasses {
		if strings.EqualFold(oc.Name, want) || oc.OID == want {
			return oc, nil
		}
	}
	return directory.ObjectClass{}, directory.Error("objectclass", directory.FieldNotFound, "object class not found")
}

func (s *Query) AttributeType(ctx context.Context, p Principal, name string) (directory.AttributeType, error) {
	sch, err := s.Schema(ctx, p)
	if err != nil {
		return directory.AttributeType{}, err
	}
	want := strings.TrimSpace(name)
	if want == "" {
		return directory.AttributeType{}, directory.Error("attribute", directory.FieldNotFound, "attribute type not found")
	}
	for _, at := range sch.Attributes {
		if strings.EqualFold(at.Name, want) || at.OID == want {
			return at, nil
		}
	}
	return directory.AttributeType{}, directory.Error("attribute", directory.FieldNotFound, "attribute type not found")
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
		if secretOrDeniedAttr(a.Name) {
			continue
		}
		out = append(out, a)
	}
	return out
}

func redactSchema(in directory.Schema) directory.Schema {
	out := directory.Schema{}
	for _, oc := range in.ObjectClasses {
		oc.Must = filterSecretNames(oc.Must)
		oc.May = filterSecretNames(oc.May)
		out.ObjectClasses = append(out.ObjectClasses, oc)
	}
	for _, at := range in.Attributes {
		if secretSchemaAttr(at.Name) {
			continue
		}
		out.Attributes = append(out.Attributes, at)
	}
	return out
}

func filterSecretNames(in []string) []string {
	if in == nil {
		return nil
	}
	var out []string
	for _, n := range in {
		if secretSchemaAttr(n) {
			continue
		}
		out = append(out, n)
	}
	if out == nil {
		return []string{}
	}
	return out
}

func secretOrDeniedAttr(name string) bool {
	canon := config.CanonicalAttr(name)
	if config.ForbiddenUserAttr(name) || canon == "userpassword" {
		return true
	}
	return secretSchemaAttr(name)
}

func secretSchemaAttr(name string) bool {
	switch config.CanonicalAttr(name) {
	case "nsslapd-rootpw", "nsslapd-rootpwstoragescheme",
		"nsmultiplexorbindcred", "nsmultiplexorcredentials",
		"nsds5replicacredentials", "userpassword":
		return true
	default:
		return strings.HasPrefix(config.CanonicalAttr(name), "nsslapd-rootpw")
	}
}
