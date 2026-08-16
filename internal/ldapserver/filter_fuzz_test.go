package ldapserver

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// This file holds the T-149 wire-filter fuzz target (parity contract C6:
// malformed filters fail safely, never panic) and its seed-corpus
// generator. The string-level RFC 4515 validator used by the control plane
// is fuzzed where it lives (internal/config FuzzParseFilter); this target
// covers the RFC 4511 Filter CHOICE decoder that runs pre-auth on every
// SearchRequest.
//
// Smoke: go test -fuzz=FuzzFilterWire -fuzztime=30s ./internal/ldapserver/

// filterWireCorpusDir is the committed seed corpus for FuzzFilterWire. The
// go test runner replays every file there automatically, in both unit and
// fuzzing modes.
const filterWireCorpusDir = "testdata/fuzz/FuzzFilterWire"

// FuzzFilterWire feeds arbitrary bytes through the BER packet decoder and
// the Filter CHOICE interpreter. Invariants:
//
//   - no panic; malformed input returns an error
//   - a filter that decodes re-encodes (encodeFilter) and the re-encoding
//     decodes to an equal tree (decode -> encode -> decode fixed point)
//
// The in-code seeds plus the committed corpus cover every filter node type;
// regenerate the corpus with LABLDAP_GOLDEN_UPDATE=1 (no credentials).
func FuzzFilterWire(f *testing.F) {
	for _, flt := range filterWireSeeds() {
		pkt, err := encodeFilter(flt, 0)
		if err != nil {
			f.Fatalf("seed filter failed to encode: %v", err)
		}
		f.Add(pkt.Bytes())
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		pkt, err := ber.DecodePacketErr(data)
		if err != nil {
			return // not BER: any error is acceptable, a panic is not
		}
		flt, err := decodeFilter(pkt)
		if err != nil {
			return // malformed filter: any error is acceptable
		}
		out, err := encodeFilter(flt, 0)
		if err != nil {
			t.Fatalf("decoded filter failed to re-encode: %v", err)
		}
		pkt2, err := ber.DecodePacketErr(out.Bytes())
		if err != nil {
			t.Fatalf("re-encoded filter failed BER decode: %v", err)
		}
		flt2, err := decodeFilter(pkt2)
		if err != nil {
			t.Fatalf("re-encoded filter failed to decode: %v", err)
		}
		if !reflect.DeepEqual(flt, flt2) {
			t.Fatalf("filter decode->encode->decode is not a fixed point:\nfirst:  %#v\nsecond: %#v", flt, flt2)
		}
	})
}

// filterWireSeeds covers every Filter node type plus edge shapes (empty
// runs, deep nesting, non-UTF8 assertion values). No credentials.
func filterWireSeeds() []Filter {
	deep := Filter(&FilterEquality{Attr: "uid", Value: []byte("alice")})
	for i := 0; i < 8; i++ {
		deep = &FilterNot{Child: deep}
	}
	return []Filter{
		&FilterEquality{Attr: "uid", Value: []byte("alice")},
		&FilterEquality{Attr: "x-bin", Value: []byte{0x00, 0xff, 0x28, 0x29}},
		&FilterPresent{Attr: "objectClass"},
		&FilterSubstrings{Attr: "cn", Initial: []byte("a"), Any: [][]byte{[]byte("b"), {}}, Final: []byte("z")},
		&FilterSubstrings{Attr: "cn", Any: [][]byte{[]byte("x")}},
		&FilterGreaterOrEqual{Attr: "uidNumber", Value: []byte("1000")},
		&FilterLessOrEqual{Attr: "uidNumber", Value: []byte("2000")},
		&FilterApproxMatch{Attr: "cn", Value: []byte("alice")},
		&FilterAnd{Children: []Filter{
			&FilterEquality{Attr: "objectClass", Value: []byte("inetOrgPerson")},
			&FilterOr{Children: []Filter{
				&FilterPresent{Attr: "mail"},
				&FilterEquality{Attr: "sn", Value: []byte("Adams")},
			}},
		}},
		&FilterAnd{}, // empty SET OF: decodes to nil children
		&FilterNot{Child: &FilterPresent{Attr: "uid"}},
		deep,
	}
}

// TestWriteFilterWireSeeds regenerates the committed FuzzFilterWire corpus.
// Skipped in normal runs; regenerate with:
//
//	LABLDAP_GOLDEN_UPDATE=1 go test ./internal/ldapserver/ -run TestWriteFilterWireSeeds
func TestWriteFilterWireSeeds(t *testing.T) {
	if os.Getenv("LABLDAP_GOLDEN_UPDATE") == "" {
		t.Skip("set LABLDAP_GOLDEN_UPDATE=1 to regenerate fuzz seeds")
	}
	writeFuzzByteSeeds(t, filterWireCorpusDir, func(i int) []byte {
		pkt, err := encodeFilter(filterWireSeeds()[i], 0)
		if err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
		return pkt.Bytes()
	}, len(filterWireSeeds()))
}

// writeFuzzByteSeeds writes n `go test fuzz v1` corpus files, each holding
// a single []byte value from gen.
func writeFuzzByteSeeds(t *testing.T, dir string, gen func(i int) []byte, n int) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		content := fmt.Sprintf("go test fuzz v1\n[]byte(%q)\n", gen(i))
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("seed%02d", i)), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("wrote %d seeds under %s", n, dir)
}
