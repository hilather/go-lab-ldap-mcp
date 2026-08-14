package ds389

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

var pluginCNs = []struct {
	name string
	cn   string
}{
	{pluginMemberOf, cnMemberOf},
	{pluginReferint, cnReferint},
}

func (e Engine) Capabilities(ctx context.Context, req bootstrap.CapabilityRequest) (bootstrap.Capabilities, error) {
	phase := req.Phase
	if phase == "" {
		phase = "inspect"
	}
	if err := ctx.Err(); err != nil {
		return bootstrap.Capabilities{}, bootstrap.PhaseError(phase, "capability", "capability inspect canceled").Wrap(err)
	}
	if req.DialTimeout <= 0 {
		req.DialTimeout = 5 * time.Second
	}
	dial := e.TreeDial
	if dial == nil {
		dial = defaultTreeDial
	}
	conn, err := dial(ctx, req.TreeRequest)
	if err != nil {
		return bootstrap.Capabilities{}, bootstrap.PhaseError(phase, "capability", "could not bind as Directory Manager to inspect capabilities").Wrap(err)
	}
	defer conn.Close()

	caps := bootstrap.Capabilities{
		AdapterVersion: observability.CurrentBuild("labldap-bootstrap").Version,
	}
	root, err := searchBase(conn, "", []string{
		"vendorName", "vendorVersion", "supportedControl", "supportedLDAPVersion",
		"namingContexts", "subschemaSubentry",
	})
	if err != nil {
		return caps, bootstrap.PhaseError(phase, "capability", "could not read the Root DSE").Wrap(err)
	}
	caps.EngineVendor = firstAttr(root, "vendorName")
	caps.EngineVersion = firstAttr(root, "vendorVersion")
	caps.Controls = uniqueSorted(root.GetAttributeValues("supportedControl"))

	caps.Transports = observedTransports(req)
	if cfg, err := searchBase(conn, "cn=config", []string{
		"nsslapd-securePort", "nsslapd-port", "nsslapd-security", "passwordStorageScheme",
	}); err == nil && cfg != nil {
		if port := firstAttr(cfg, "nsslapd-securePort"); port != "" && port != "0" {
			caps.Transports = appendUnique(caps.Transports, "ldaps")
		}
		if strings.EqualFold(firstAttr(cfg, "nsslapd-security"), "on") {
			caps.Transports = appendUnique(caps.Transports, "ldaps")
		}
		caps.PasswordScheme = firstAttr(cfg, "passwordStorageScheme")
	}
	if caps.PasswordScheme == "" {
		caps.PasswordScheme = e.readScheme(ctx, req)
	}
	caps.Transports = uniqueSorted(caps.Transports)

	for _, p := range pluginCNs {
		dn := "cn=" + p.cn + ",cn=plugins,cn=config"
		ent, err := searchBase(conn, dn, []string{"nsslapd-pluginEnabled", "cn"})
		if err != nil {
			continue
		}
		if strings.EqualFold(firstAttr(ent, "nsslapd-pluginEnabled"), "on") {
			caps.Plugins = append(caps.Plugins, p.name)
		}
	}
	if schemaHasAccountLock(conn) {
		caps.Plugins = appendUnique(caps.Plugins, pluginDisable)
	}
	caps.Plugins = uniqueSorted(caps.Plugins)
	caps.RequiredOK = requiredCapabilitiesOK(caps, req)
	return caps, nil
}

func (e Engine) Inspect(ctx context.Context, req bootstrap.DriftRequest) (bootstrap.DriftReport, error) {
	if err := ctx.Err(); err != nil {
		return bootstrap.DriftReport{}, bootstrap.PhaseError("drift", "drift", "drift inspect canceled").Wrap(err)
	}
	if req.DialTimeout <= 0 {
		req.DialTimeout = 5 * time.Second
	}
	dial := e.TreeDial
	if dial == nil {
		dial = defaultTreeDial
	}
	conn, err := dial(ctx, req.TreeRequest)
	if err != nil {
		return bootstrap.DriftReport{}, bootstrap.PhaseError("drift", "drift", "could not bind as Directory Manager to inspect drift").Wrap(err)
	}
	defer conn.Close()

	keep := driftKeep(req)
	rep := bootstrap.DriftReport{
		ExpectedUsers:    sortedDNs(userDNs(req.Users)),
		ExpectedGroups:   sortedDNs(groupDNs(req.Groups)),
		ExpectedACIs:     sortedStrings(aciIDs(req.ACIs)),
		ExpectedRevision: req.DirectoryRevision,
	}

	people, err := listChildren(conn, req.PeopleDN, []string{"dn", "objectClass"})
	if err != nil && !isNoSuchObject(err) {
		return rep, bootstrap.PhaseError("drift", "drift", "could not list people entries").Wrap(err)
	}
	groups, err := listChildren(conn, req.GroupsDN, []string{"dn", "objectClass"})
	if err != nil && !isNoSuchObject(err) {
		return rep, bootstrap.PhaseError("drift", "drift", "could not list group entries").Wrap(err)
	}
	for _, e := range people {
		if kept(keep, e.DN) {
			continue
		}
		rep.LiveUsers = append(rep.LiveUsers, e.DN)
	}
	for _, e := range groups {
		if kept(keep, e.DN) {
			continue
		}
		rep.LiveGroups = append(rep.LiveGroups, e.DN)
	}
	rep.LiveUsers = sortedDNs(rep.LiveUsers)
	rep.LiveGroups = sortedDNs(rep.LiveGroups)
	rep.ExtraUsers, rep.MissingUsers = diffDNs(rep.LiveUsers, rep.ExpectedUsers)
	rep.ExtraGroups, rep.MissingGroups = diffDNs(rep.LiveGroups, rep.ExpectedGroups)

	rep.LiveACIs = liveOwnedACIs(conn, req.ACIs)
	rep.ExtraACIs, rep.MissingACIs = diffStrings(rep.LiveACIs, rep.ExpectedACIs)

	markerDN := req.MarkerDN
	if markerDN == "" && req.Suffix != "" {
		markerDN = "cn=" + markerCN + "," + req.Suffix
	}
	if markerDN != "" {
		m, err := readMarkerEntry(conn, markerDN)
		if err != nil {
			return rep, err
		}
		rep.MarkerRevision = m.AppliedRevision
	}
	rep.Differ = len(rep.ExtraUsers) > 0 || len(rep.MissingUsers) > 0 ||
		len(rep.ExtraGroups) > 0 || len(rep.MissingGroups) > 0 ||
		len(rep.ExtraACIs) > 0 || len(rep.MissingACIs) > 0 ||
		rep.MarkerRevision != rep.ExpectedRevision
	return rep, nil
}

func (e Engine) readScheme(ctx context.Context, req bootstrap.CapabilityRequest) string {
	if req.PasswordFile == "" {
		return ""
	}
	raw, err := e.Runner.JSON(ctx, req.PasswordFile, req.Instance, []string{"pwpolicy", "get"})
	if err != nil {
		return ""
	}
	attrs, err := parsePolicyAttrs(raw)
	if err != nil {
		return ""
	}
	return first(attrs, "passwordstoragescheme")
}

func observedTransports(req bootstrap.CapabilityRequest) []string {
	var out []string
	if req.UseLDAPS || strings.HasPrefix(req.LDAPURL, "ldaps://") {
		out = append(out, "ldaps")
	}
	if req.StartTLS {
		out = append(out, "starttls")
	}
	return out
}

func schemaHasAccountLock(conn treeConn) bool {
	ent, err := searchBase(conn, "cn=schema", []string{"attributeTypes"})
	if err != nil || ent == nil {
		return false
	}
	for _, v := range ent.GetAttributeValues("attributeTypes") {
		if strings.Contains(strings.ToLower(v), "nsaccountlock") {
			return true
		}
	}
	return false
}

func requiredCapabilitiesOK(caps bootstrap.Capabilities, req bootstrap.CapabilityRequest) bool {
	if caps.EngineVendor == "" && caps.EngineVersion == "" && len(caps.Controls) == 0 && len(caps.Plugins) == 0 {
		return false
	}
	wantPlugins := req.RequiredPlugins
	if len(wantPlugins) == 0 {
		wantPlugins = []string{pluginMemberOf, pluginReferint, pluginDisable}
	}
	have := map[string]struct{}{}
	for _, p := range caps.Plugins {
		have[strings.ToLower(p)] = struct{}{}
	}
	for _, p := range wantPlugins {
		if _, ok := have[strings.ToLower(p)]; !ok {
			return false
		}
	}
	if len(req.RequiredTransports) > 0 {
		haveT := map[string]struct{}{}
		for _, t := range caps.Transports {
			haveT[strings.ToLower(t)] = struct{}{}
		}
		for _, t := range req.RequiredTransports {
			if _, ok := haveT[strings.ToLower(t)]; !ok {
				return false
			}
		}
	}
	if req.RequiredScheme != "" && !schemeMatch(caps.PasswordScheme, req.RequiredScheme) {
		return false
	}
	return true
}

func schemeMatch(got, want string) bool {
	norm := func(s string) string {
		return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), "_", "-"))
	}
	return norm(got) == norm(want)
}

func driftKeep(req bootstrap.DriftRequest) map[string]struct{} {
	out := map[string]struct{}{}
	add := func(s string) {
		if s == "" {
			return
		}
		out[dnKey(s)] = struct{}{}
	}
	add(req.RuntimeDN)
	add(req.PeopleDN)
	add(req.GroupsDN)
	add(req.Suffix)
	add(req.MarkerDN)
	for _, p := range req.Preserve {
		add(p)
	}
	return out
}

func userDNs(users []config.NormalizedUser) []string {
	out := make([]string, 0, len(users))
	for _, u := range users {
		if u.DN != "" {
			out = append(out, u.DN)
		}
	}
	return out
}

func groupDNs(groups []config.NormalizedGroup) []string {
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		if g.DN != "" {
			out = append(out, g.DN)
		}
	}
	return out
}

func aciIDs(acis []config.NamedACI) []string {
	out := make([]string, 0, len(acis))
	for _, a := range acis {
		if a.ID != "" {
			out = append(out, a.ID)
		}
	}
	return out
}

func liveOwnedACIs(conn treeConn, planned []config.NamedACI) []string {
	seen := map[string]struct{}{}
	var targets []string
	for _, a := range planned {
		if a.Target == "" {
			continue
		}
		key := dnKey(a.Target)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, a.Target)
	}
	ids := map[string]struct{}{}
	for _, t := range targets {
		vals, err := readACIs(conn, t)
		if err != nil {
			continue
		}
		for id := range ownedByName(vals) {
			ids[id] = struct{}{}
		}
	}
	out := make([]string, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	return sortedStrings(out)
}

func diffDNs(live, expected []string) (extra, missing []string) {
	return diffStrings(normalizeDNList(live), normalizeDNList(expected))
}

func normalizeDNList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, dnKey(s))
	}
	return sortedStrings(out)
}

func diffStrings(live, expected []string) (extra, missing []string) {
	have := map[string]struct{}{}
	want := map[string]struct{}{}
	for _, s := range live {
		have[s] = struct{}{}
	}
	for _, s := range expected {
		want[s] = struct{}{}
	}
	for _, s := range live {
		if _, ok := want[s]; !ok {
			extra = append(extra, s)
		}
	}
	for _, s := range expected {
		if _, ok := have[s]; !ok {
			missing = append(missing, s)
		}
	}
	return extra, missing
}

func sortedDNs(in []string) []string {
	out := append([]string(nil), in...)
	sort.Slice(out, func(i, j int) bool { return dnKey(out[i]) < dnKey(out[j]) })
	return out
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func uniqueSorted(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		key := strings.ToLower(s)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func appendUnique(in []string, v string) []string {
	for _, s := range in {
		if strings.EqualFold(s, v) {
			return in
		}
	}
	return append(in, v)
}
