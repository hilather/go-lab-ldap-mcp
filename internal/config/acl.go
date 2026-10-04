package config

import (
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1"
	"github.com/hilather/go-lab-ldap-mcp/internal/schema389"
)

var (
	aciIDRe   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)
	aciAttrRe = regexp.MustCompile(`^(\*|[A-Za-z][A-Za-z0-9-;]*)$`)
)

var aciPerms = map[string]string{
	"read": "read", "search": "search", "compare": "compare",
	"add": "add", "delete": "delete", "write": "write",
}

func compileACIs(n *Normalized) ([]NamedACI, error) {
	var acc []*apperr.Error
	var ops []NamedACI
	seen := map[string]struct{}{}
	for _, a := range n.OperatorACLs {
		if a.ID == "" {
			acc = append(acc, fieldErr("spec.acls", "required", "acl id is required"))
			continue
		}
		if strings.HasPrefix(a.ID, "runtime-") {
			acc = append(acc, fieldErr("spec.acls."+a.ID, "runtime_aci_override", "operator ACL cannot use a runtime- reserved id"))
			continue
		}
		if _, ok := seen[a.ID]; ok {
			acc = append(acc, fieldErr("spec.acls."+a.ID, "duplicate", "duplicate ACL id"))
			continue
		}
		seen[a.ID] = struct{}{}
		if !aciIDRe.MatchString(a.ID) {
			acc = append(acc, fieldErr("spec.acls."+a.ID, "invalid_id", "ACL id is not a safe identifier"))
			continue
		}
		if a.RawACI != "" {
			if !n.AllowRawACI {
				acc = append(acc, fieldErr("spec.acls."+a.ID+".rawACI", "raw_aci_disabled", "raw ACI requires directory.allowRawACI"))
				continue
			}
			if err := rejectCNConfig(a.RawACI, n.Suffix); err != nil {
				acc = append(acc, err)
				continue
			}
			ops = append(ops, NamedACI{ID: "labldap:" + a.ID, Target: n.Suffix.String(), Text: a.RawACI})
			continue
		}
		text, tgt, err := emitACI(a, n)
		if err != nil {
			acc = append(acc, asConfigErr(err))
			continue
		}
		ops = append(ops, NamedACI{ID: "labldap:" + a.ID, Target: tgt, Text: text})
	}
	runtime := managedRuntimeACIs(n)
	if err := joinConfig(acc); err != nil {
		return nil, err
	}
	return append(runtime, ops...), nil
}

func managedRuntimeACIs(n *Normalized) []NamedACI {
	suf := n.Suffix.String()
	people := n.PeopleDN.String()
	groups := n.GroupsDN.String()
	who := `userdn="ldap:///` + aciEscape(n.Runtime.DN) + `"`
	out := []NamedACI{
		namedRuntime("runtime-suffix-read", suf, who, []string{"read", "search", "compare"}, "*", "userPassword"),
		namedRuntime("runtime-people-write", people, who, []string{"add", "delete", "write", "read", "search", "compare"}, "*", "aci"),
		namedRuntime("runtime-groups-write", groups, who, []string{"add", "delete", "write", "read", "search", "compare"}, "*", "aci"),
		namedRuntime("runtime-password", people, who, []string{"write"}, "userPassword", ""),
	}
	for i, extra := range n.AdditionalSuffixes {
		id := strconv.Itoa(i + 1)
		dn := extra.String()
		out = append(out,
			namedRuntime("runtime-addsuffix-"+id+"-read", dn, who, []string{"read", "search", "compare"}, "*", "userPassword"),
			namedRuntime("runtime-addsuffix-"+id+"-write", dn, who, []string{"add", "delete", "write", "read", "search", "compare"}, "*", "aci"),
			namedRuntime("runtime-addsuffix-"+id+"-password", dn, who, []string{"write"}, "userPassword", ""),
		)
	}
	return out
}

func namedRuntime(id, target, who string, perms []string, allow, deny string) NamedACI {
	if who == "" {
		who = `userdn="ldap:///all"`
	}
	b := aciBuilder{name: "labldap:" + id, targetDN: target, perms: perms, allow: allow, deny: deny, who: who}
	// principal is the runtime account; we use a bound userdn of the runtime DN when present
	return NamedACI{ID: "labldap:" + id, Target: target, Text: b.String()}
}

type aciBuilder struct {
	name     string
	targetDN string
	perms    []string
	allow    string
	deny     string
	who      string
}

func (b aciBuilder) String() string {
	var sb strings.Builder
	sb.WriteString(`(target="ldap:///`)
	sb.WriteString(aciEscape(b.targetDN))
	sb.WriteString(`")`)
	if b.deny != "" {
		sb.WriteString(`(targetattr!="`)
		sb.WriteString(b.deny)
		sb.WriteString(`")`)
	} else if b.allow != "" && b.allow != "*" {
		sb.WriteString(`(targetattr="`)
		sb.WriteString(b.allow)
		sb.WriteString(`")`)
	} else {
		sb.WriteString(`(targetattr="*")`)
	}
	sb.WriteString(`(version 3.0; acl "`)
	sb.WriteString(b.name)
	sb.WriteString(`"; allow (`)
	sb.WriteString(strings.Join(b.perms, ","))
	sb.WriteString(`) `)
	sb.WriteString(b.who)
	sb.WriteString(`;)`)
	return sb.String()
}

func emitACI(a v1alpha1.ACL, n *Normalized) (string, string, error) {
	tgt, err := targetDN(a.Target, n)
	if err != nil {
		return "", "", err
	}
	if err := rejectCNConfig(tgt, n.Suffix); err != nil {
		return "", "", err
	}
	if a.Principal.Kind == "runtime" {
		return "", "", fieldErr("spec.acls."+a.ID+".principal", "cn_config_grant", "runtime principal cannot be assigned extra targets via DSL")
	}
	who, err := principalWho(a.Principal, n)
	if err != nil {
		return "", "", err
	}
	var perms []string
	for _, p := range a.Permissions {
		canon, ok := aciPerms[p]
		if !ok {
			return "", "", fieldErr("spec.acls."+a.ID+".permissions", "invalid_permission", "permission is not allowed")
		}
		perms = append(perms, canon)
	}
	if len(perms) == 0 {
		return "", "", fieldErr("spec.acls."+a.ID+".permissions", "required", "at least one permission is required")
	}
	// CAND-33: every listed name must be a valid targetattr spelling that
	// the pinned 389 schema defines, as 389 rejects the ACI otherwise
	// (oracle probe 16). dslTargetAttr then builds the clause.
	for _, l := range []struct {
		field string
		names []string
	}{{"allow", a.Attributes.Allow}, {"deny", a.Attributes.Deny}} {
		for _, name := range l.names {
			if !aciAttrRe.MatchString(name) {
				return "", "", fieldErr("spec.acls."+a.ID+".attributes."+l.field, "invalid_attribute", "attribute name is not allowed")
			}
			if name != "*" && !schema389.Known(name) {
				return "", "", fieldErr("spec.acls."+a.ID+".attributes."+l.field, "unknown_attribute", "attribute is not defined in the 389 schema")
			}
		}
	}
	allow, deny, err := dslTargetAttr(a)
	if err != nil {
		return "", "", err
	}
	b := aciBuilder{name: "labldap:" + a.ID, targetDN: tgt, perms: perms, allow: allow, deny: deny, who: who}
	return b.String(), tgt, nil
}

// MaxACIAttrs bounds the names in one emitted targetattr list; it equals
// the native parser's limit (ldapserver aciMaxAttrsA, kept in sync by a
// test there).
const MaxACIAttrs = 64

// dslTargetAttr turns attributes.allow/deny into the allow or deny string
// for aciBuilder (resolved DSL follow-up, oracle probe 25: lists are
// 389 "a || b" lists). Allow alone: targetattr="a || b" ("*" anywhere, or
// no list, means every attribute). Deny with an allow list that is empty
// or holds "*": targetattr!="a || b". Both: the allow names a deny name
// does not cover (same base after alias resolution, deny options a subset
// of the allow name's, as targetattr options work since CAND-34); a
// same-base deny that cannot be expressed that way, an empty result, and
// any deny "*" (it would leave no attribute, or compile to
// targetattr!="*", which still grants entry-level add/delete) are
// rejected.
func dslTargetAttr(a v1alpha1.ACL) (allow, deny string, err error) {
	path := "spec.acls." + a.ID + ".attributes."
	for _, l := range []struct {
		field string
		names []string
	}{{"allow", a.Attributes.Allow}, {"deny", a.Attributes.Deny}} {
		if len(l.names) > MaxACIAttrs {
			return "", "", fieldErr(path+l.field, "too_many_attributes", "too many attribute names in one list")
		}
	}
	allowAll := len(a.Attributes.Allow) == 0
	for _, n := range a.Attributes.Allow {
		if n == "*" {
			allowAll = true
		}
	}
	for _, n := range a.Attributes.Deny {
		if n == "*" {
			return "", "", fieldErr(path+"deny", "invalid_attribute_filter", `deny "*" leaves no attribute; remove the ACL or narrow it`)
		}
	}
	join := func(field string, names []string) (string, error) {
		names = dedupFold(names)
		if len(names) > MaxACIAttrs {
			return "", fieldErr(path+field, "too_many_attributes", "too many attribute names in one list")
		}
		return strings.Join(names, " || "), nil
	}
	switch {
	case len(a.Attributes.Deny) == 0 && allowAll:
		return "*", "", nil
	case len(a.Attributes.Deny) == 0:
		allow, err = join("allow", a.Attributes.Allow)
		return allow, "", err
	case allowAll:
		deny, err = join("deny", a.Attributes.Deny)
		return "", deny, err
	}
	var kept []string
	for _, an := range a.Attributes.Allow {
		aBase, aOpts := splitDSLAttr(an)
		drop := false
		for _, dn := range a.Attributes.Deny {
			dBase, dOpts := splitDSLAttr(dn)
			if !strings.EqualFold(aBase, dBase) || slices.Contains(dOpts, "") {
				// A name with an empty option ("mail;") covers nothing.
				continue
			}
			if !optionSubset(dOpts, aOpts) {
				return "", "", fieldErr(path+"deny", "invalid_attribute_filter", "a deny name with options narrower than an allow name of the same attribute cannot be expressed as one ACI")
			}
			drop = true
		}
		if !drop {
			kept = append(kept, an)
		}
	}
	if len(kept) == 0 {
		return "", "", fieldErr(path+"deny", "invalid_attribute_filter", "no attribute is left after removing the denied names")
	}
	allow, err = join("allow", kept)
	return allow, "", err
}

// splitDSLAttr returns a DSL attribute name's canonical base (aliases
// resolved, so rfc822Mailbox and mail compare equal) and its options.
func splitDSLAttr(name string) (string, []string) {
	base, rest, _ := strings.Cut(name, ";")
	var opts []string
	if rest != "" || strings.Contains(name, ";") {
		opts = strings.Split(rest, ";")
	}
	return CanonicalAttrType(base), opts
}

// optionSubset reports whether every option in sub appears in set
// (case-insensitive). An empty option never matches, as in targetattr.
func optionSubset(sub, set []string) bool {
	for _, o := range sub {
		found := false
		for _, h := range set {
			if o != "" && strings.EqualFold(o, h) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// dedupFold drops case-insensitive duplicates, keeping the first spelling.
func dedupFold(names []string) []string {
	out := make([]string, 0, len(names))
	seen := map[string]bool{}
	for _, n := range names {
		k := strings.ToLower(n)
		if !seen[k] {
			seen[k] = true
			out = append(out, n)
		}
	}
	return out
}

func targetDN(t v1alpha1.Target, n *Normalized) (string, error) {
	switch t.Kind {
	case v1alpha1.TargetSuffix, "":
		return n.Suffix.String(), nil
	case "people", "users":
		return n.PeopleDN.String(), nil
	case v1alpha1.TargetGroups:
		return n.GroupsDN.String(), nil
	case v1alpha1.TargetEntry, "dn":
		d, err := ParseDN(t.DN)
		if err != nil {
			return "", fieldErr("spec.acls.target.dn", "invalid_dn", "target DN is invalid")
		}
		if !n.UnderManaged(d) {
			return "", fieldErr("spec.acls.target.dn", "outside_suffix", "target DN is outside the managed suffix")
		}
		return d.String(), nil
	default:
		return "", fieldErr("spec.acls.target.kind", "invalid_enum", "unknown target kind")
	}
}

func principalWho(p v1alpha1.Principal, n *Normalized) (string, error) {
	switch p.Kind {
	case v1alpha1.PrincipalGroup:
		for _, g := range n.Groups {
			if g.ID == p.Ref {
				return `groupdn="ldap:///` + aciEscape(g.DN) + `"`, nil
			}
		}
		return "", fieldErr("spec.acls.principal.ref", "missing_ref", "ACL group principal is not defined")
	case v1alpha1.PrincipalUser:
		for _, u := range n.Users {
			if u.ID == p.Ref {
				return `userdn="ldap:///` + aciEscape(u.DN) + `"`, nil
			}
		}
		return "", fieldErr("spec.acls.principal.ref", "missing_ref", "ACL user principal is not defined")
	case "anyone":
		return `userdn="ldap:///anyone"`, nil
	default:
		return "", fieldErr("spec.acls.principal.kind", "invalid_enum", "unknown principal kind")
	}
}

func aciEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '(':
			b.WriteString(`\28`)
		case ')':
			b.WriteString(`\29`)
		case '\n', '\r':
			b.WriteString(`\0a`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func rejectCNConfig(s string, suffix DN) *apperr.Error {
	compact := strings.ToLower(strings.ReplaceAll(s, " ", ""))
	if strings.Contains(compact, "cn=config") {
		return fieldErr("spec.acls", "cn_config_grant", "ACL must not grant cn=config")
	}
	if d, err := ParseDN(s); err == nil {
		cfg, _ := ParseDN("cn=config")
		if d.Equal(cfg) || cfg.IsDescendantOf(d) {
			return fieldErr("spec.acls", "cn_config_grant", "ACL must not grant cn=config")
		}
		if !d.Equal(suffix) && !d.IsDescendantOf(suffix) && strings.Contains(s, "=") {
			// raw ACI may be a full clause, not a DN — skip outside-suffix if parse is a DN that isn't config
		}
	}
	return nil
}
