//go:build integration

package parity

import (
	"os"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

// TestDualEngineParity is the T-147 dual-engine run: the same operation
// sequences against the in-process native engine and the pinned 389
// oracle.
//
//   - Contract cases: any outcome mismatch FAILS the build (Contract rows
//     are not negotiable; a genuine 389 quirk must become a logged Delta
//     first).
//   - CAND probes: both engines' outcomes are recorded into the delta
//     ledger; a "delta" verdict is a REPORT, not a failure.
//   - The committed delta-ledger.json is a golden file: drift in either
//     engine's observed behavior fails here. Regenerate deliberately with
//     PARITY_UPDATE_LEDGER=1.
func TestDualEngineParity(t *testing.T) {
	fx := compileFixture(t)
	native := startNative(t, fx)
	defer native.close(t)
	oracle := startOracle(t, fx) // skips when Docker is unavailable
	defer oracle.close(t)

	update := os.Getenv(ledgerUpdateEnv) == "1"
	fresh := &deltaLedger{Version: ledgerVersion, Oracle: ledgerOracleRef(t)}

	// --- Contract tier: identical outcomes required. ---
	nativeCases := map[string]ledgerCaseEntry{}
	oracleCases := map[string]ledgerCaseEntry{}
	t.Run("contract-native", func(t *testing.T) {
		for _, e := range runContract(t, fx, native) {
			nativeCases[e.ID+"/"+e.Name] = e
		}
	})
	t.Run("contract-oracle", func(t *testing.T) {
		for _, e := range runContract(t, fx, oracle) {
			oracleCases[e.ID+"/"+e.Name] = e
		}
	})
	for _, cs := range contractCases {
		key := cs.id + "/" + cs.name
		nc, oc := nativeCases[key], oracleCases[key]
		fresh.Contract = append(fresh.Contract, nc)
		if !outcomesEqual(nc.Agreed, oc.Agreed) {
			t.Errorf("CONTRACT MISMATCH %s (not a logged Delta — this fails the build):\n%s",
				key, diffOutcomes(key, oc.Agreed, nc.Agreed))
		}
	}

	// --- Delta candidates: record, don't fail. ---
	nativeCands := map[string][]opOutcome{}
	oracleCands := map[string][]opOutcome{}
	t.Run("candidates-native", func(t *testing.T) {
		nativeCands = runCandidates(t, fx, native)
	})
	t.Run("candidates-oracle", func(t *testing.T) {
		oracleCands = runCandidates(t, fx, oracle)
	})
	for _, p := range candProbes {
		no, oo := nativeCands[p.id], oracleCands[p.id]
		entry := ledgerCandEntry{
			ID: p.id, Topic: p.topic,
			Verdict: verdictFor(oo, no),
			Oracle:  oo, Native: no,
		}
		fresh.Candidates = append(fresh.Candidates, entry)
		t.Logf("candidate %s (%s): verdict=%s", p.id, p.topic, entry.Verdict)
	}

	// --- Deltas whose *difference* is asserted (contract section 3). ---
	t.Run("delta-D1-vendor-identity", func(t *testing.T) {
		assertDeltaD1(t, native, oracle)
	})

	// --- Golden ledger: drift fails; update mode rewrites. ---
	t.Run("delta-ledger", func(t *testing.T) {
		if update {
			writeLedger(t, fresh)
		}
		golden := loadLedger(t)
		assertLedgerEqual(t, golden, fresh)
	})
}

// ledgerOracleRef records the pinned oracle image reference for
// provenance. The digest pin makes the golden reproducible.
func ledgerOracleRef(t *testing.T) string {
	t.Helper()
	ref, err := parityImageRef()
	if err != nil || ref == "" {
		return ledgerOracleName
	}
	return ref
}

// assertDeltaD1 proves D1: both engines publish vendor identity, and the
// values deliberately differ (native must not fake 389 identity). The
// read is authenticated: pre-bind DSE access is CAND-22, not D1.
func assertDeltaD1(t *testing.T, native, oracle engine) {
	t.Helper()
	read := func(e engine) (string, string) {
		conn := mustDial(t, e, userSpec(userDN("alice"), userPasswords["alice"]))
		defer conn.Close()
		req := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
			0, 0, false, "(objectClass=*)", []string{"vendorName", "vendorVersion"}, nil)
		res, err := conn.Search(req)
		if err != nil || res == nil || len(res.Entries) != 1 {
			t.Fatalf("%s root DSE read: err=%v", e.name(), err)
		}
		entry := res.Entries[0]
		return entry.GetAttributeValue("vendorName"), entry.GetAttributeValue("vendorVersion")
	}
	nName, nVer := read(native)
	oName, oVer := read(oracle)
	if nName == "" || nVer == "" || oName == "" || oVer == "" {
		t.Fatalf("vendor identity must be published: native=(%q,%q) oracle=(%q,%q)", nName, nVer, oName, oVer)
	}
	if strings.EqualFold(nName, oName) {
		t.Fatalf("D1 violated: native fakes the 389 vendorName %q", nName)
	}
	if !strings.Contains(oName, "389") {
		t.Fatalf("oracle sanity: expected 389 vendor identity, got %q", oName)
	}
}

// assertLedgerEqual compares the committed golden against the freshly
// observed ledger.
func assertLedgerEqual(t *testing.T, golden, fresh *deltaLedger) {
	t.Helper()
	if golden.Version != fresh.Version {
		t.Fatalf("ledger version %q, suite produces %q", golden.Version, fresh.Version)
	}
	if len(golden.Contract) != len(fresh.Contract) || len(golden.Candidates) != len(fresh.Candidates) {
		t.Fatalf("ledger shape drift: contract %d→%d, candidates %d→%d — regenerate with %s=1",
			len(golden.Contract), len(fresh.Contract), len(golden.Candidates), len(fresh.Candidates), ledgerUpdateEnv)
	}
	for i, want := range golden.Contract {
		got := fresh.Contract[i]
		if want.ID != got.ID || want.Name != got.Name {
			t.Fatalf("contract case order drift: golden[%d]=%s/%s fresh=%s/%s", i, want.ID, want.Name, got.ID, got.Name)
		}
		if !outcomesEqual(want.Agreed, got.Agreed) {
			t.Errorf("contract case %s/%s drifted from the adjudicated ledger:\n%s",
				want.ID, want.Name, diffOutcomes(want.Name, want.Agreed, got.Agreed))
		}
	}
	for i, want := range golden.Candidates {
		got := fresh.Candidates[i]
		if want.ID != got.ID {
			t.Fatalf("candidate order drift: golden[%d]=%s fresh=%s", i, want.ID, got.ID)
		}
		if want.Verdict != got.Verdict {
			t.Errorf("candidate %s verdict changed %s → %s:\noracle: %s\nnative: %s",
				want.ID, want.Verdict, got.Verdict,
				diffOutcomes(want.ID, want.Oracle, got.Oracle), diffOutcomes(want.ID, want.Native, got.Native))
		}
		if !outcomesEqual(want.Oracle, got.Oracle) {
			t.Errorf("candidate %s oracle column drifted:\n%s", want.ID, diffOutcomes(want.ID, want.Oracle, got.Oracle))
		}
		if !outcomesEqual(want.Native, got.Native) {
			t.Errorf("candidate %s native column drifted:\n%s", want.ID, diffOutcomes(want.ID, want.Native, got.Native))
		}
	}
}
