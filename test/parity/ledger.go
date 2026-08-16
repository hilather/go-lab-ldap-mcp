package parity

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

// The delta ledger (test/parity/delta-ledger.json) is the
// machine-readable adjudication record T-150 consumes (contract section
// 5 rule 7, TASKS.md T-147). It is a golden file: the integration run
// fails when observed behavior drifts from it, and it is only rewritten
// deliberately via PARITY_UPDATE_LEDGER=1.
const (
	ledgerFile       = "delta-ledger.json"
	ledgerUpdateEnv  = "PARITY_UPDATE_LEDGER"
	ledgerVersion    = "labldap.parity.v1"
	ledgerOracleName = "389-ds (pinned, see deploy/docker/dirsrv.digest)"
)

// deltaLedger is the on-disk adjudication record.
type deltaLedger struct {
	Version    string            `json:"version"`
	Oracle     string            `json:"oracle"`
	Contract   []ledgerCaseEntry `json:"contract"`
	Candidates []ledgerCandEntry `json:"candidates"`
}

// ledgerCaseEntry locks the agreed Contract outcome set ("agreed" holds
// the canonical outcome sequence both engines produced).
type ledgerCaseEntry struct {
	ID     string      `json:"id"`
	Name   string      `json:"name"`
	Agreed []opOutcome `json:"agreed"`
}

// ledgerCandEntry is one adjudicated Delta candidate: both engines'
// outcome columns plus the verdict.
type ledgerCandEntry struct {
	ID      string      `json:"id"`
	Topic   string      `json:"topic"`
	Verdict string      `json:"verdict"` // "match" | "delta"
	Oracle  []opOutcome `json:"oracle"`
	Native  []opOutcome `json:"native"`
}

// verdictFor compares the two engine columns.
func verdictFor(oracle, native []opOutcome) string {
	if outcomesEqual(oracle, native) {
		return "match"
	}
	return "delta"
}

// loadLedger reads the committed golden ledger.
func loadLedger(t *testing.T) *deltaLedger {
	t.Helper()
	raw, err := os.ReadFile(ledgerPath())
	if err != nil {
		t.Fatalf("parity: read %s: %v (run with -tags integration and %s=1 to create it)", ledgerFile, err, ledgerUpdateEnv)
	}
	var l deltaLedger
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatalf("parity: parse %s: %v", ledgerFile, err)
	}
	return &l
}

func ledgerPath() string {
	// Tests run with the package directory as CWD.
	return filepath.Join(ledgerFile)
}

// writeLedger rewrites the golden file (update mode only).
func writeLedger(t *testing.T, l *deltaLedger) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(l); err != nil {
		t.Fatalf("parity: encode ledger: %v", err)
	}
	if err := os.WriteFile(ledgerPath(), buf.Bytes(), 0o644); err != nil {
		t.Fatalf("parity: write %s: %v", ledgerFile, err)
	}
	t.Logf("parity: %s rewritten (%s=1)", ledgerFile, ledgerUpdateEnv)
}

// outcomesEqual compares outcome sequences exactly, treating nil and
// empty containers as identical (JSON round-trips with omitempty lose
// the distinction, and it carries no semantic weight).
func outcomesEqual(a, b []opOutcome) bool {
	return reflect.DeepEqual(canonicalOutcomes(a), canonicalOutcomes(b))
}

// canonicalOutcomes returns a copy with all nil containers made empty.
func canonicalOutcomes(outs []opOutcome) []opOutcome {
	cp := make([]opOutcome, len(outs))
	for i, o := range outs {
		cp[i] = o
		if cp[i].Entries == nil {
			cp[i].Entries = []canonEntry{}
		}
		entries := make([]canonEntry, len(o.Entries))
		for j, e := range o.Entries {
			entries[j] = e
			if entries[j].Attrs == nil {
				entries[j].Attrs = map[string][]string{}
			}
		}
		cp[i].Entries = entries
	}
	return cp
}

// diffOutcomes renders a compact first-difference description for
// failures. It never prints secrets: outcomes are canonicalized before
// they get here (secretAttrs are dropped at capture time).
func diffOutcomes(caseName string, oracle, native []opOutcome) string {
	if len(oracle) != len(native) {
		return "step count differs: oracle=" + itoa(len(oracle)) + " native=" + itoa(len(native))
	}
	for i := range oracle {
		if !reflect.DeepEqual(oracle[i], native[i]) {
			oj, _ := json.Marshal(oracle[i])
			nj, _ := json.Marshal(native[i])
			return "step " + itoa(i) + " of " + caseName + ":\n  oracle: " + string(oj) + "\n  native: " + string(nj)
		}
	}
	return ""
}

func itoa(n int) string { return strconv.Itoa(n) }
