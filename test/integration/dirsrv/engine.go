package dirsrv

import (
	"os"
	"strings"
	"testing"
)

// T-148 engine parametrization (TASKS.md T-148; the Contract/Delta/Excluded
// ledger is docs/design/native-engine-parity-contract.md).
//
// The integration suite runs against one of two directory engines, selected
// by the LABLDAP_IT_ENGINE environment variable:
//
//	389ds   default. The pinned 389 Directory Server container harness
//	        (harness.go). `make test-integration` runs this and is unchanged.
//	native  opt-in. An in-process labldapd-equivalent fixture (native.go):
//	        the real internal/ldapserver stack on loopback with ephemeral
//	        ports and a bbolt store in t.TempDir, seeded through the same
//	        LDAP-as-Directory-Manager bootstrap data plane the 389 run uses
//	        (ADR-0009 decision 12). `make test-integration-native` runs it.
//
// Skip ledger — the only tests skipped under engine=native, each naming the
// parity-contract Delta/Excluded ID that covers it:
//
//	D2  admin plane: dsconf/cn=config read-back, plugin CN and nsslapd-*
//	    assertions, in-container ldap* probes of the admin tree. labldapd
//	    self-applies the engine plan at start; there is no dsconf.
//	D4  on-disk format / image lifecycle: pinned-image contract, bootstrap
//	    image contents, container restart/recover, compose stack topology.
//	D5  backend name: dsconf backend suffix list "(userroot)" naming.
//	E7  389 tooling: dsconf/dsctl exist only in the 389 image.
//
// Everything not listed here is Contract and must run against both engines
// with the same directory-visible expectations.
const (
	Engine389DS  = "389ds"
	EngineNative = "native"
)

// EngineEnvVar selects the integration engine (see the ledger above).
const EngineEnvVar = "LABLDAP_IT_ENGINE"

// itEngine resolves the selected engine, failing on an unknown value so a
// typo never silently reruns the 389 suite.
func itEngine(t *testing.T) string {
	t.Helper()
	switch e := os.Getenv(EngineEnvVar); e {
	case "", Engine389DS:
		return Engine389DS
	case EngineNative:
		return EngineNative
	default:
		t.Fatalf("%s=%q: want %q or %q", EngineEnvVar, e, Engine389DS, EngineNative)
		return ""
	}
}

// skip389Only skips a test that is bound to the 389 container harness when
// the native engine is selected. delta must name the parity-contract Delta
// or Excluded ID (D1-D7, E1-E8) covering the difference; the skip list is
// the ledger at the top of engine.go.
func skip389Only(t *testing.T, delta, what string) {
	t.Helper()
	if itEngine(t) == EngineNative {
		t.Skipf("389-only under %s=native: %s (parity contract %s)", EngineEnvVar, what, delta)
	}
}

// withITEngine injects spec.directory.engine matching LABLDAP_IT_ENGINE
// (default 389ds) into a scenario that omits it. After v0.3.0 the compile
// default is native; the 389 integration suite would otherwise wire the
// native cn=config read-back reconcilers and fail with engine_mismatch.
// YAML that already sets engine is left unchanged so an explicit fixture
// cannot be silently rewritten.
func withITEngine(src string) string {
	if strings.Contains(src, "engine:") {
		return src
	}
	engine := os.Getenv(EngineEnvVar)
	if engine == "" {
		engine = Engine389DS
	}
	const needle = "directory: { suffix:"
	if strings.Contains(src, needle) {
		return strings.Replace(src, needle, "directory: { engine: "+engine+", suffix:", 1)
	}
	const flow = "directory: {"
	if i := strings.Index(src, flow); i >= 0 {
		return src[:i] + "directory: { engine: " + engine + "," + src[i+len(flow):]
	}
	const block = "directory:"
	if i := strings.Index(src, block); i >= 0 {
		rest := src[i+len(block):]
		nl := strings.IndexByte(rest, '\n')
		if nl >= 0 && strings.TrimSpace(rest[:nl]) == "" {
			after := rest[nl+1:]
			indent := leadingWS(after)
			if indent != "" {
				return src[:i+len(block)] + rest[:nl+1] + indent + "engine: " + engine + "\n" + after
			}
		}
	}
	return src
}

func leadingWS(s string) string {
	n := 0
	for n < len(s) && (s[n] == ' ' || s[n] == '\t') {
		n++
	}
	return s[:n]
}
