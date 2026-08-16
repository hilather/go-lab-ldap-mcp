package dirsrv

import (
	"os"
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
// Skip ledger — skip389Only is valid only for tests that truly need dsconf,
// on-disk image lifecycle, backend CN, or 389 tooling (D2/D4/D5/E7).
// Contract tests must use startRuntimeEnv / startEngine (engineDial) and
// host-LDAP helpers — they must not call Start().
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
