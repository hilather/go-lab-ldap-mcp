package ds389

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

type schemaCache struct {
	mu        sync.Mutex
	dse       directory.RootDSE
	dseOK     bool
	dseExp    time.Time
	schema    directory.Schema
	schemaOK  bool
	schemaExp time.Time
}

func (c *schemaCache) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dseOK = false
	c.schemaOK = false
	c.dse = directory.RootDSE{}
	c.schema = directory.Schema{}
}

var rootDSEAttrs = []string{
	"namingContexts", "vendorName", "vendorVersion",
	"supportedControl", "supportedSASLMechanisms", "subschemaSubentry",
}

func (r *Runtime) RootDSE(ctx context.Context) (directory.RootDSE, error) {
	now := r.now()
	r.cache.mu.Lock()
	if r.cache.dseOK && now.Before(r.cache.dseExp) {
		out := r.cache.dse
		r.cache.mu.Unlock()
		return out, nil
	}
	r.cache.mu.Unlock()

	dse, err := r.fetchRootDSE(ctx)
	if err != nil {
		r.cache.invalidate()
		return directory.RootDSE{}, err
	}
	r.noteAssertion(dse)
	r.cache.mu.Lock()
	r.cache.dse = dse
	r.cache.dseOK = true
	r.cache.dseExp = now.Add(r.cfg.SchemaTTL)
	r.cache.mu.Unlock()
	return dse, nil
}

func (r *Runtime) Schema(ctx context.Context) (directory.Schema, error) {
	now := r.now()
	r.cache.mu.Lock()
	if r.cache.schemaOK && now.Before(r.cache.schemaExp) {
		out := r.cache.schema
		r.cache.mu.Unlock()
		return out, nil
	}
	r.cache.mu.Unlock()

	sch, err := r.fetchSchema(ctx)
	if err != nil {
		r.cache.invalidate()
		return directory.Schema{}, err
	}
	r.cache.mu.Lock()
	r.cache.schema = sch
	r.cache.schemaOK = true
	r.cache.schemaExp = now.Add(r.cfg.SchemaTTL)
	r.cache.mu.Unlock()
	return sch, nil
}

func (r *Runtime) Capabilities(ctx context.Context) (directory.Capabilities, error) {
	dse, err := r.RootDSE(ctx)
	if err != nil {
		return directory.Capabilities{}, err
	}
	caps := directory.Capabilities{
		EngineVendor:   dse.VendorName,
		EngineVersion:  dse.VendorVersion,
		AdapterVersion: observability.CurrentBuild("labldap").Version,
		Controls:       append([]string(nil), dse.SupportedControls...),
		RequiredOK:     dse.VendorName != "" || dse.VendorVersion != "" || len(dse.NamingContexts) > 0,
	}
	if r.cfg.Client.Transport != "" {
		caps.Transports = []string{string(r.cfg.Client.Transport)}
	}
	caps.ManagedSuffixes = r.managedSuffixStrings()
	if r.cfg.Suffix != "" {
		ok := false
		for _, nc := range dse.NamingContexts {
			if sameDN(nc, r.cfg.Suffix) {
				ok = true
				break
			}
		}
		caps.RequiredOK = caps.RequiredOK && ok
	}
	return caps, nil
}

func (r *Runtime) fetchRootDSE(ctx context.Context) (directory.RootDSE, error) {
	size, seconds := r.searchLimits()
	var out directory.RootDSE
	err := r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		res, e := c.Search(ctx, &ldap.SearchRequest{
			BaseDN:       "",
			Scope:        ldap.ScopeBaseObject,
			DerefAliases: ldap.NeverDerefAliases,
			SizeLimit:    1,
			TimeLimit:    seconds,
			Filter:       "(objectClass=*)",
			Attributes:   rootDSEAttrs,
		})
		if e != nil {
			return e
		}
		if len(res.Entries) == 0 {
			return directory.Error("rootdse", directory.FieldUnavailable, "Root DSE is empty")
		}
		out = rootDSEFromEntry(res.Entries[0])
		_ = size
		return nil
	})
	return out, err
}

func (r *Runtime) fetchSchema(ctx context.Context) (directory.Schema, error) {
	dse, err := r.RootDSE(ctx)
	if err != nil {
		return directory.Schema{}, err
	}
	sub := "cn=schema"
	size, seconds := r.searchLimits()
	var out directory.Schema
	err = r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		if subEntry, e := searchBaseConn(ctx, c, "", []string{"subschemaSubentry"}, 1, seconds); e == nil {
			if v := subEntry.GetAttributeValue("subschemaSubentry"); v != "" {
				sub = v
			}
		}
		_ = dse
		ent, e := searchBaseConn(ctx, c, sub, []string{"objectClasses", "attributeTypes"}, size, seconds)
		if e != nil {
			return e
		}
		out = schemaFromEntry(ent)
		return nil
	})
	return out, err
}

func rootDSEFromEntry(e *ldap.Entry) directory.RootDSE {
	if e == nil {
		return directory.RootDSE{}
	}
	return directory.RootDSE{
		NamingContexts:    sortCI(e.GetAttributeValues("namingContexts")),
		VendorName:        e.GetAttributeValue("vendorName"),
		VendorVersion:     e.GetAttributeValue("vendorVersion"),
		SupportedControls: sortCI(e.GetAttributeValues("supportedControl")),
		SupportedSASL:     sortCI(e.GetAttributeValues("supportedSASLMechanisms")),
	}
}

func secretSchemaName(name string) bool {
	switch config.CanonicalAttr(name) {
	case "nsslapd-rootpw", "nsslapd-rootpwstoragescheme",
		"nsmultiplexorbindcred", "nsmultiplexorcredentials",
		"nsds5replicacredentials":
		return true
	default:
		return false
	}
}

func schemaFromEntry(e *ldap.Entry) directory.Schema {
	if e == nil {
		return directory.Schema{}
	}
	var ocs []directory.ObjectClass
	for _, raw := range e.GetAttributeValues("objectClasses") {
		if oc, ok := parseObjectClass(raw); ok {
			ocs = append(ocs, oc)
		}
	}
	var ats []directory.AttributeType
	for _, raw := range e.GetAttributeValues("attributeTypes") {
		if at, ok := parseAttributeType(raw); ok && !secretSchemaName(at.Name) {
			ats = append(ats, at)
		}
	}
	return directory.Schema{
		ObjectClasses: sortObjectClasses(ocs),
		Attributes:    sortAttributeTypes(ats),
	}
}

func parseObjectClass(raw string) (directory.ObjectClass, bool) {
	p := newSchemaParser(raw)
	oid, ok := p.oid()
	if !ok {
		return directory.ObjectClass{}, false
	}
	oc := directory.ObjectClass{OID: oid, Kind: "structural"}
	for !p.done() {
		kw := strings.ToUpper(p.keyword())
		switch kw {
		case "NAME":
			names := p.names()
			if len(names) > 0 {
				oc.Name = names[0]
			}
		case "DESC":
			p.quoted()
		case "SUP":
			oc.Sup = p.oids()
		case "STRUCTURAL":
			oc.Kind = "structural"
		case "ABSTRACT":
			oc.Kind = "abstract"
		case "AUXILIARY":
			oc.Kind = "auxiliary"
		case "MUST":
			oc.Must = p.oids()
		case "MAY":
			oc.May = p.oids()
		case "":
			return oc, oc.Name != "" || oc.OID != ""
		default:
			p.skipValue()
		}
	}
	return oc, oc.Name != "" || oc.OID != ""
}

func parseAttributeType(raw string) (directory.AttributeType, bool) {
	p := newSchemaParser(raw)
	oid, ok := p.oid()
	if !ok {
		return directory.AttributeType{}, false
	}
	at := directory.AttributeType{OID: oid}
	for !p.done() {
		kw := strings.ToUpper(p.keyword())
		switch kw {
		case "NAME":
			names := p.names()
			if len(names) > 0 {
				at.Name = names[0]
			}
		case "DESC":
			p.quoted()
		case "SYNTAX":
			at.Syntax, _ = p.oid()
			p.skipLen()
		case "SINGLE-VALUE":
			at.SingleValue = true
		case "":
			return at, at.Name != "" || at.OID != ""
		default:
			p.skipValue()
		}
	}
	return at, at.Name != "" || at.OID != ""
}

type schemaParser struct {
	s string
	i int
}

func newSchemaParser(s string) *schemaParser {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "(")
	s = strings.TrimSuffix(strings.TrimSpace(s), ")")
	return &schemaParser{s: strings.TrimSpace(s)}
}

func (p *schemaParser) done() bool {
	p.skipSpace()
	return p.i >= len(p.s)
}

func (p *schemaParser) skipSpace() {
	for p.i < len(p.s) && unicode.IsSpace(rune(p.s[p.i])) {
		p.i++
	}
}

func (p *schemaParser) peek() byte {
	if p.i >= len(p.s) {
		return 0
	}
	return p.s[p.i]
}

func (p *schemaParser) keyword() string {
	p.skipSpace()
	start := p.i
	for p.i < len(p.s) {
		c := p.s[p.i]
		if unicode.IsSpace(rune(c)) || c == '(' || c == '\'' {
			break
		}
		p.i++
	}
	return p.s[start:p.i]
}

func (p *schemaParser) oid() (string, bool) {
	p.skipSpace()
	if p.i >= len(p.s) {
		return "", false
	}
	if p.peek() == '\'' {
		return p.quoted(), true
	}
	start := p.i
	for p.i < len(p.s) {
		c := p.s[p.i]
		if unicode.IsSpace(rune(c)) || c == '{' || c == ')' {
			break
		}
		p.i++
	}
	v := p.s[start:p.i]
	return v, v != ""
}

func (p *schemaParser) quoted() string {
	p.skipSpace()
	if p.peek() != '\'' {
		s, _ := p.oid()
		return s
	}
	p.i++
	start := p.i
	for p.i < len(p.s) && p.s[p.i] != '\'' {
		p.i++
	}
	v := p.s[start:p.i]
	if p.i < len(p.s) {
		p.i++
	}
	return v
}

func (p *schemaParser) names() []string {
	p.skipSpace()
	if p.peek() != '(' {
		if n := p.quoted(); n != "" {
			return []string{n}
		}
		return nil
	}
	p.i++
	var out []string
	for !p.done() && p.peek() != ')' {
		if n := p.quoted(); n != "" {
			out = append(out, n)
		} else {
			break
		}
		p.skipSpace()
	}
	if p.peek() == ')' {
		p.i++
	}
	return out
}

func (p *schemaParser) oids() []string {
	p.skipSpace()
	if p.peek() != '(' {
		if s, ok := p.oid(); ok {
			return []string{s}
		}
		return nil
	}
	p.i++
	var out []string
	for !p.done() && p.peek() != ')' {
		p.skipSpace()
		if p.peek() == '$' {
			p.i++
			continue
		}
		if s, ok := p.oid(); ok {
			out = append(out, s)
		} else {
			break
		}
	}
	if p.peek() == ')' {
		p.i++
	}
	return out
}

func (p *schemaParser) skipLen() {
	p.skipSpace()
	if p.peek() != '{' {
		return
	}
	for p.i < len(p.s) && p.s[p.i] != '}' {
		p.i++
	}
	if p.i < len(p.s) {
		p.i++
	}
}

func (p *schemaParser) skipValue() {
	p.skipSpace()
	switch p.peek() {
	case '\'':
		p.quoted()
	case '(':
		depth := 0
		for p.i < len(p.s) {
			switch p.s[p.i] {
			case '(':
				depth++
			case ')':
				depth--
				p.i++
				if depth == 0 {
					return
				}
				continue
			}
			p.i++
		}
	default:
		if p.i < len(p.s) && (p.s[p.i] == 'X' || p.s[p.i] == 'x') {
			return
		}
		_, _ = p.oid()
	}
}

func sortObjectClasses(in []directory.ObjectClass) []directory.ObjectClass {
	out := append([]directory.ObjectClass(nil), in...)
	for i := range out {
		out[i].Must = sortCI(out[i].Must)
		out[i].May = sortCI(out[i].May)
		out[i].Sup = sortCI(out[i].Sup)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
		}
		return out[i].OID < out[j].OID
	})
	return out
}

func sortAttributeTypes(in []directory.AttributeType) []directory.AttributeType {
	out := append([]directory.AttributeType(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
		}
		return out[i].OID < out[j].OID
	})
	return out
}
