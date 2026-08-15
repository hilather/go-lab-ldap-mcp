package ldapserver

// Tests for the BER codec (T-124). All credentials appearing in fixtures
// (e.g. "test-password") are synthetic test data, never valid anywhere;
// they exist so the golden PDUs are deterministic and reviewable.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const (
	goldenDir     = "testdata/codec"
	fuzzCorpusDir = "testdata/fuzz/FuzzDecode"
)

// ---------------------------------------------------------------------------
// builders (test-only BER writers; the codec under test is what validates them)
// ---------------------------------------------------------------------------

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// tlv wraps content in a definite-form TLV with a proper length encoding.
func tlv(tag byte, content ...byte) []byte {
	n := len(content)
	var hdr []byte
	switch {
	case n < 0x80:
		hdr = []byte{tag, byte(n)}
	case n < 0x100:
		hdr = []byte{tag, 0x81, byte(n)}
	case n < 0x10000:
		hdr = []byte{tag, 0x82, byte(n >> 8), byte(n)}
	default:
		hdr = []byte{tag, 0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return append(hdr, content...)
}

// nestedNot wraps a present filter in depth levels of [2] NOT.
func nestedNot(depth int) []byte {
	inner := tlv(0x87, []byte("objectClass")...)
	for i := 0; i < depth; i++ {
		inner = tlv(0xa2, inner...)
	}
	return inner
}

// searchPDU builds a SearchRequest PDU (msgid 1) around the given filter TLV.
func searchPDU(fil []byte) []byte {
	body := bytes.Join([][]byte{
		tlv(0x04, []byte("dc=example,dc=test")...), // baseObject
		tlv(0x0a, 0x02), // scope wholeSubtree
		tlv(0x0a, 0x00), // deref never
		tlv(0x02, 0x00), // sizeLimit
		tlv(0x02, 0x00), // timeLimit
		tlv(0x01, 0x00), // typesOnly false
		fil,
		tlv(0x30), // empty attribute selection
	}, nil)
	return tlv(0x30, append(tlv(0x02, 0x01), tlv(0x63, body...)...)...)
}

// ---------------------------------------------------------------------------
// golden RFC 4511 PDUs
// ---------------------------------------------------------------------------

// goldenPDUs is the single source of truth for the committed vectors under
// testdata/codec. TestGoldenPDUs verifies decode(golden) == model and
// encode(model) == golden bytes; TestWriteGoldens regenerates the files.
func goldenPDUs() map[string]*Message {
	return map[string]*Message{
		"bind_request_anonymous": {
			ID: 1,
			Op: &BindRequest{Version: 3},
		},
		"bind_request_simple": {
			ID: 2,
			Op: &BindRequest{
				Version:  3,
				Name:     "cn=Directory Manager",
				Password: []byte("test-password"), // fixture only, not a real credential
			},
		},
		"bind_response_invalid_credentials": {
			ID: 2,
			Op: &BindResponse{Result: Result{Code: ResultInvalidCredentials}},
		},
		"unbind_request": {ID: 3, Op: &UnbindRequest{}},
		"abandon_request": {
			ID: 4,
			Op: &AbandonRequest{MessageID: 2},
		},
		"search_request_subtree_equality": {
			ID: 5,
			Op: &SearchRequest{
				BaseDN:     "ou=people,dc=example,dc=test",
				Scope:      ScopeWholeSubtree,
				Deref:      DerefNever,
				SizeLimit:  100,
				TimeLimit:  30,
				TypesOnly:  false,
				Filter:     &FilterEquality{Attr: "uid", Value: []byte("alice")},
				Attributes: []string{"uid", "cn", "mail"},
			},
		},
		"search_request_complex_filter": {
			ID: 6,
			Op: &SearchRequest{
				BaseDN:    "ou=people,dc=example,dc=test",
				Scope:     ScopeSingleLevel,
				Deref:     DerefAlways,
				TypesOnly: true,
				Filter: &FilterAnd{Children: []Filter{
					&FilterPresent{Attr: "objectClass"},
					&FilterOr{Children: []Filter{
						&FilterNot{Child: &FilterApproxMatch{Attr: "cn", Value: []byte("alice")}},
						&FilterSubstrings{Attr: "cn", Initial: []byte("al"), Any: [][]byte{[]byte("i")}, Final: []byte("e")},
					}},
					&FilterGreaterOrEqual{Attr: "uidNumber", Value: []byte("1000")},
					&FilterLessOrEqual{Attr: "uidNumber", Value: []byte("2000")},
				}},
			},
		},
		"search_result_entry": {
			ID: 5,
			Op: &SearchResultEntry{
				DN: "uid=alice,ou=people,dc=example,dc=test",
				Attributes: []Attribute{
					{Name: "uid", Values: [][]byte{[]byte("alice")}},
					{Name: "cn", Values: [][]byte{[]byte("Alice Adams"), []byte("Alice A.")}},
					{Name: "userCertificate;binary", Values: [][]byte{{0x00, 0x01, 0xff, 0x80}}},
				},
			},
		},
		"search_result_done": {
			ID: 5,
			Op: &SearchResultDone{Result: Result{Code: ResultSuccess}},
		},
		"modify_request": {
			ID: 7,
			Op: &ModifyRequest{
				DN: "uid=alice,ou=people,dc=example,dc=test",
				Changes: []ModifyChange{
					{Op: ModifyReplace, Attr: Attribute{Name: "displayName", Values: [][]byte{[]byte("Alice A. Adams")}}},
					{Op: ModifyAdd, Attr: Attribute{Name: "description", Values: [][]byte{[]byte("fixture account")}}},
					{Op: ModifyDelete, Attr: Attribute{Name: "seeAlso"}},
				},
			},
		},
		"modify_response_success": {
			ID: 7,
			Op: &ModifyResponse{Result: Result{Code: ResultSuccess}},
		},
		"add_request": {
			ID: 8,
			Op: &AddRequest{
				DN: "uid=bob,ou=people,dc=example,dc=test",
				Attributes: []Attribute{
					{Name: "objectClass", Values: [][]byte{[]byte("person"), []byte("organizationalPerson"), []byte("inetOrgPerson")}},
					{Name: "uid", Values: [][]byte{[]byte("bob")}},
					{Name: "sn", Values: [][]byte{[]byte("Brown")}},
					{Name: "cn", Values: [][]byte{[]byte("Bob Brown")}},
				},
			},
		},
		"add_response_success": {
			ID: 8,
			Op: &AddResponse{Result: Result{Code: ResultSuccess}},
		},
		"delete_request": {
			ID: 9,
			Op: &DeleteRequest{DN: "uid=bob,ou=people,dc=example,dc=test"},
		},
		"modifydn_request": {
			ID: 10,
			Op: &ModifyDNRequest{
				DN:           "uid=bob,ou=people,dc=example,dc=test",
				NewRDN:       "uid=robert",
				DeleteOldRDN: true,
				NewSuperior:  "ou=people,dc=example,dc=test",
			},
		},
		"modifydn_request_no_superior": {
			ID: 14,
			Op: &ModifyDNRequest{
				DN:     "uid=bob,ou=people,dc=example,dc=test",
				NewRDN: "uid=robert",
			},
		},
		"compare_request": {
			ID: 11,
			Op: &CompareRequest{
				DN:    "uid=alice,ou=people,dc=example,dc=test",
				Attr:  "uid",
				Value: []byte("alice"),
			},
		},
		"compare_response_true": {
			ID: 11,
			Op: &CompareResponse{Result: Result{Code: ResultCompareTrue}},
		},
		"extended_request_whoami": {
			ID: 12,
			Op: &ExtendedRequest{Name: OIDWhoAmI},
		},
		"extended_response_whoami": {
			ID: 12,
			Op: &ExtendedResponse{
				Result: Result{Code: ResultSuccess},
				Name:   OIDWhoAmI,
				Value:  []byte("dn:uid=alice,ou=people,dc=example,dc=test"),
			},
		},
		"bind_request_controls": {
			ID: 13,
			Op: &BindRequest{Version: 3},
			Controls: []Control{
				{ // RFC 2696 paged results: size 20, empty cookie
					OID:      OIDSimplePagedResults,
					Critical: true,
					Value:    []byte{0x30, 0x06, 0x02, 0x01, 0x14, 0x04, 0x01, 0x00},
				},
				{OID: "2.16.840.1.113730.3.4.2"}, // RFC 3296 ManageDsaIT, no value
			},
		},
	}
}

func sortedGoldenNames() []string {
	names := make([]string, 0, len(goldenPDUs()))
	for name := range goldenPDUs() {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(goldenDir, name+".hex"))
	if err != nil {
		t.Fatalf("read golden %s: %v (run LABLDAP_GOLDEN_UPDATE=1 go test -run TestWriteGoldens)", name, err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("golden %s is not hex: %v", name, err)
	}
	return raw
}

func encodeMsg(t *testing.T, c *BERCodec, m *Message) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := c.WriteMessage(context.Background(), &buf, m); err != nil {
		t.Fatalf("encode %T: %v", m.Op, err)
	}
	return buf.Bytes()
}

func decodeMsg(t *testing.T, c *BERCodec, data []byte) *Message {
	t.Helper()
	m, err := c.ReadMessage(context.Background(), bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return m
}

func checkMessagesEqual(t *testing.T, got, want *Message) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("message mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestGoldenPDUs(t *testing.T) {
	codec := NewBERCodec(BERCodecOptions{})
	for _, name := range sortedGoldenNames() {
		t.Run(name, func(t *testing.T) {
			raw := readGolden(t, name)
			want := goldenPDUs()[name]

			got := decodeMsg(t, codec, raw)
			checkMessagesEqual(t, got, want)

			// encode(model) must reproduce the golden bytes exactly, and a
			// decode->encode cycle must be byte-stable.
			enc := encodeMsg(t, codec, want)
			if !bytes.Equal(enc, raw) {
				t.Fatalf("encode mismatch for %s:\n got: %x\nwant: %x", name, enc, raw)
			}
			enc2 := encodeMsg(t, codec, got)
			if !bytes.Equal(enc2, raw) {
				t.Fatalf("decode->encode not byte-stable for %s:\n got: %x\nwant: %x", name, enc2, raw)
			}
		})
	}
}

// TestWriteGoldens regenerates the committed golden files and the fuzz seed
// corpus. It is skipped in normal runs; regenerate with:
//
//	LABLDAP_GOLDEN_UPDATE=1 go test ./internal/ldapserver/ -run TestWriteGoldens
func TestWriteGoldens(t *testing.T) {
	if os.Getenv("LABLDAP_GOLDEN_UPDATE") == "" {
		t.Skip("set LABLDAP_GOLDEN_UPDATE=1 to regenerate golden PDUs and fuzz seeds")
	}
	codec := NewBERCodec(BERCodecOptions{})
	if err := os.MkdirAll(goldenDir, 0o755); err != nil {
		t.Fatal(err)
	}
	seeds := rawSeeds()
	for _, name := range sortedGoldenNames() {
		enc := encodeMsg(t, codec, goldenPDUs()[name])
		if err := os.WriteFile(filepath.Join(goldenDir, name+".hex"), []byte(hex.EncodeToString(enc)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		seeds = append(seeds, enc)
	}
	if err := os.MkdirAll(fuzzCorpusDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i, s := range seeds {
		content := fmt.Sprintf("go test fuzz v1\n[]byte(%q)\n", s)
		if err := os.WriteFile(filepath.Join(fuzzCorpusDir, fmt.Sprintf("seed%02d", i)), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("wrote %d goldens and %d fuzz seeds", len(goldenPDUs()), len(seeds))
}

// rawSeeds returns adversarial raw inputs for the fuzz corpus. None contain
// credentials.
func rawSeeds() [][]byte {
	anon := tlv(0x30, append(tlv(0x02, 0x01),
		tlv(0x60, append(append(tlv(0x02, 0x03), tlv(0x04)...), tlv(0x80)...)...)...)...)
	return [][]byte{
		{},                                      // empty stream
		{0x30},                                  // lone tag
		{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff},    // huge length claim, no body
		{0x30, 0x80, 0x00, 0x00},                // indefinite length
		{0x30, 0xff},                            // reserved length form
		{0x30, 0x89, 1, 2, 3, 4, 5, 6, 7, 8, 9}, // >8 length octets
		anon,
		anon[:len(anon)/2], // truncated bind
		{0x31, 0x05, 0x02, 0x01, 0x01, 0x42, 0x00}, // wrong outer class
		{0x30, 0x05, 0x02, 0x01, 0x03, 0x42, 0x00}, // unbind
		searchPDU(nestedNot(200)),                  // beyond depth budget
		searchPDU(nestedNot(30)),                   // within depth budget
	}
}

// TestRFCAnchorVectors pins byte-exact encodings derived from RFC 4511 by
// hand, so the golden files cannot silently drift from the specification.
func TestRFCAnchorVectors(t *testing.T) {
	codec := NewBERCodec(BERCodecOptions{})
	cases := []struct {
		name string
		hex  string
		msg  *Message
	}{
		{
			name: "anonymous bind",
			hex:  "300c020101600702010304008000",
			msg:  &Message{ID: 1, Op: &BindRequest{Version: 3}},
		},
		{
			name: "unbind",
			hex:  "30050201034200",
			msg:  &Message{ID: 3, Op: &UnbindRequest{}},
		},
		{
			name: "search result done",
			hex:  "300c02010265070a010004000400",
			msg:  &Message{ID: 2, Op: &SearchResultDone{Result: Result{Code: ResultSuccess}}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := mustHex(t, tc.hex)
			checkMessagesEqual(t, decodeMsg(t, codec, raw), tc.msg)
			if enc := encodeMsg(t, codec, tc.msg); !bytes.Equal(enc, raw) {
				t.Fatalf("encode mismatch:\n got: %x\nwant: %x", enc, raw)
			}
		})
	}
}

// TestRoundTripAllOps exercises encode->decode equality for every operation
// in the pinned model, plus decode->encode->decode stability.
func TestRoundTripAllOps(t *testing.T) {
	codec := NewBERCodec(BERCodecOptions{})
	msgs := []*Message{
		{ID: 0, Op: &UnbindRequest{}},
		{ID: 1, Op: &BindRequest{Version: 3}},
		{ID: 2, Op: &BindRequest{Version: 3, Name: "uid=alice,ou=people,dc=example,dc=test", Password: []byte("test-password")}},
		{ID: 3, Op: &BindResponse{Result: Result{Code: ResultSuccess}}},
		{ID: 4, Op: &AbandonRequest{MessageID: 3}},
		{ID: 5, Op: &SearchRequest{
			BaseDN: "dc=example,dc=test",
			Scope:  ScopeBaseObject,
			Filter: &FilterPresent{Attr: "objectClass"},
		}},
		{ID: 6, Op: &SearchRequest{
			BaseDN:    "ou=people,dc=example,dc=test",
			Scope:     ScopeChildren,
			Deref:     DerefInSearching,
			SizeLimit: 500,
			TimeLimit: 60,
			Filter: &FilterNot{Child: &FilterAnd{Children: []Filter{
				&FilterEquality{Attr: "uid", Value: []byte("mallory")},
				&FilterOr{Children: []Filter{
					&FilterSubstrings{Attr: "cn", Any: [][]byte{[]byte("admin")}},
					&FilterGreaterOrEqual{Attr: "uidNumber", Value: []byte("0")},
					&FilterLessOrEqual{Attr: "loginGraceLimit", Value: []byte("3")},
					&FilterApproxMatch{Attr: "sn", Value: []byte("smith")},
				}},
			}}},
			Attributes: []string{"1.1"},
		}},
		{ID: 7, Op: &SearchResultEntry{DN: "dc=example,dc=test"}},
		{ID: 8, Op: &SearchResultEntry{
			DN: "uid=alice,ou=people,dc=example,dc=test",
			Attributes: []Attribute{
				{Name: "uid", Values: [][]byte{[]byte("alice")}},
				{Name: "jpegPhoto", Values: [][]byte{{0xff, 0xd8, 0xff, 0xe0}}},
			},
		}},
		{ID: 9, Op: &SearchResultDone{Result: Result{Code: ResultSizeLimitExceeded, DiagnosticMessage: "limit reached"}}},
		{ID: 10, Op: &ModifyRequest{
			DN: "uid=alice,ou=people,dc=example,dc=test",
			Changes: []ModifyChange{
				{Op: ModifyAdd, Attr: Attribute{Name: "description", Values: [][]byte{[]byte("x")}}},
				{Op: ModifyDelete, Attr: Attribute{Name: "seeAlso"}},
				{Op: ModifyReplace, Attr: Attribute{Name: "displayName", Values: [][]byte{[]byte("y")}}},
			},
		}},
		{ID: 11, Op: &ModifyResponse{Result: Result{Code: ResultSuccess}}},
		{ID: 12, Op: &AddRequest{
			DN: "uid=carol,ou=people,dc=example,dc=test",
			Attributes: []Attribute{
				{Name: "objectClass", Values: [][]byte{[]byte("inetOrgPerson")}},
				{Name: "cn", Values: [][]byte{[]byte("Carol C")}},
			},
		}},
		{ID: 13, Op: &AddResponse{Result: Result{Code: ResultEntryAlreadyExists, MatchedDN: "ou=people,dc=example,dc=test"}}},
		{ID: 14, Op: &DeleteRequest{DN: "uid=carol,ou=people,dc=example,dc=test"}},
		{ID: 15, Op: &DeleteResponse{Result: Result{Code: ResultNoSuchObject}}},
		{ID: 16, Op: &ModifyDNRequest{
			DN:           "uid=carol,ou=people,dc=example,dc=test",
			NewRDN:       "uid=caroline",
			DeleteOldRDN: true,
			NewSuperior:  "ou=staff,dc=example,dc=test",
		}},
		{ID: 17, Op: &ModifyDNResponse{Result: Result{Code: ResultSuccess}}},
		{ID: 18, Op: &CompareRequest{DN: "uid=alice,ou=people,dc=example,dc=test", Attr: "memberOf", Value: []byte("cn=ops,ou=groups,dc=example,dc=test")}},
		{ID: 19, Op: &CompareResponse{Result: Result{Code: ResultCompareFalse}}},
		{ID: 20, Op: &ExtendedRequest{Name: OIDWhoAmI}},
		{ID: 21, Op: &ExtendedRequest{Name: OIDStartTLS, Value: []byte{0x01, 0x02}}},
		{ID: 22, Op: &ExtendedResponse{Result: Result{Code: ResultSuccess}, Name: OIDWhoAmI, Value: []byte("dn:")}},
		{ID: 23, Op: &ExtendedResponse{Result: Result{Code: ResultUnavailableCriticalExtension, DiagnosticMessage: "unsupported"}}},
		{ID: math.MaxInt32, Op: &UnbindRequest{}},
		{ID: 25, Op: &SearchRequest{ // empty substring runs must round-trip
			BaseDN: "dc=example,dc=test",
			Filter: &FilterSubstrings{Attr: "cn", Initial: []byte{}, Any: [][]byte{{}}, Final: []byte{}},
		}},
		{
			ID: 24,
			Op: &SearchRequest{BaseDN: "dc=example,dc=test", Filter: &FilterPresent{Attr: "objectClass"}},
			Controls: []Control{
				{OID: OIDSimplePagedResults, Value: []byte{0x30, 0x06, 0x02, 0x01, 0x64, 0x04, 0x01, 0x00}},
				{OID: "2.16.840.1.113730.3.4.2", Critical: true},
				{OID: OIDAssertion, Value: []byte{0xa3, 0x08, 0x04, 0x02, 'c', 'n', 0x04, 0x02, 'b', 'o'}},
			},
		},
	}
	for i, want := range msgs {
		t.Run(fmt.Sprintf("op_%d_%T", i, want.Op), func(t *testing.T) {
			enc := encodeMsg(t, codec, want)
			got := decodeMsg(t, codec, enc)
			checkMessagesEqual(t, got, want)
			// decoded form must re-encode to the same bytes
			enc2 := encodeMsg(t, codec, got)
			if !bytes.Equal(enc2, enc) {
				t.Fatalf("decoded form not byte-stable:\nfirst:  %x\nsecond: %x", enc, enc2)
			}
			ZeroSecrets(got)
		})
	}
}

// ---------------------------------------------------------------------------
// framing limits
// ---------------------------------------------------------------------------

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// TestOversizedPDURejectedBeforeAllocation crafts a header claiming ~2 GiB
// over a short stream and asserts the codec rejects it after reading only the
// header bytes — the body buffer is never allocated or read.
func TestOversizedPDURejectedBeforeAllocation(t *testing.T) {
	codec := NewBERCodec(BERCodecOptions{})
	claim := append([]byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff}, bytes.Repeat([]byte{0x41}, 256)...)
	cr := &countingReader{r: bytes.NewReader(claim)}
	_, err := codec.ReadMessage(context.Background(), cr)
	if !errors.Is(err, ErrPDUTooLarge) {
		t.Fatalf("want ErrPDUTooLarge, got %v", err)
	}
	if cr.n != 6 {
		t.Fatalf("codec read %d bytes; want exactly the 6 header bytes (no body read, no body allocation)", cr.n)
	}
}

// TestPDULengthBoundary checks the exact-limit edge: a declared length equal
// to the limit is read (and then fails on the short stream), while limit+1 is
// rejected up front.
func TestPDULengthBoundary(t *testing.T) {
	// MaxPDUBytes bounds the whole PDU (header + content): with a 2-byte
	// header and limit 32, a declared content length of 30 is exactly at the
	// limit and 31 is over it.
	codec := NewBERCodec(BERCodecOptions{MaxPDUBytes: 32, MaxDepth: defaultMaxDepth, MaxElements: defaultMaxElements})

	atLimit := append([]byte{0x30, 0x1e}, bytes.Repeat([]byte{0x00}, 5)...)
	_, err := codec.ReadMessage(context.Background(), bytes.NewReader(atLimit))
	if errors.Is(err, ErrPDUTooLarge) {
		t.Fatalf("PDU of exactly MaxPDUBytes must not be rejected by the size check: %v", err)
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short body at exact limit: want ErrUnexpectedEOF, got %v", err)
	}

	overLimit := []byte{0x30, 0x1f}
	_, err = codec.ReadMessage(context.Background(), bytes.NewReader(overLimit))
	if !errors.Is(err, ErrPDUTooLarge) {
		t.Fatalf("one byte over the limit: want ErrPDUTooLarge, got %v", err)
	}
}

// TestTruncatedPrefixes feeds every proper prefix of every golden PDU: all
// must fail with a clean error, none may panic or decode.
func TestTruncatedPrefixes(t *testing.T) {
	codec := NewBERCodec(BERCodecOptions{})
	for _, name := range sortedGoldenNames() {
		raw := readGolden(t, name)
		for i := 0; i < len(raw); i++ {
			_, err := codec.ReadMessage(context.Background(), bytes.NewReader(raw[:i]))
			if err == nil {
				t.Fatalf("%s prefix %d decoded successfully; all prefixes must fail", name, i)
			}
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) &&
				!errors.Is(err, ErrMalformedPDU) && !errors.Is(err, ErrPDUTooLarge) {
				t.Fatalf("%s prefix %d: unexpected error class %v", name, i, err)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// malformed and hostile inputs
// ---------------------------------------------------------------------------

func TestMalformedPDUs(t *testing.T) {
	codec := NewBERCodec(BERCodecOptions{})
	unbindBody := tlv(0x42) // unbind content: empty

	cases := []struct {
		name string
		pdu  []byte
		want error
	}{
		{"wrong outer class", tlv(0x31, append(tlv(0x02, 0x01), unbindBody...)...), ErrMalformedPDU},
		{"high-tag outer", append([]byte{0x3f, 0x30, 0x03}, 0x42, 0x00), ErrMalformedPDU},
		{"indefinite length", []byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x42, 0x00, 0x00, 0x00}, ErrMalformedPDU},
		{"reserved length form", []byte{0x30, 0xff, 0x00}, ErrMalformedPDU},
		{"overwide length", []byte{0x30, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 5}, ErrMalformedPDU},
		{"empty sequence", []byte{0x30, 0x00}, ErrMalformedPDU},
		{"message id not integer", tlv(0x30, append(tlv(0x04, 0x01), unbindBody...)...), ErrMalformedPDU},
		{"message id negative", tlv(0x30, append(tlv(0x02, 0xff), unbindBody...)...), ErrMalformedPDU},
		{"message id over maxInt32", tlv(0x30, append(tlv(0x02, 0x00, 0x80, 0x00, 0x00, 0x00), unbindBody...)...), ErrMalformedPDU},
		{"op not application class", tlv(0x30, append(tlv(0x02, 0x01), tlv(0x02, 0x01)...)...), ErrMalformedPDU},
		{"entry object name mis-tagged", tlv(0x30, append(tlv(0x02, 0x01), tlv(0x64, tlv(0x02, 0x05)...)...)...), ErrMalformedPDU},
		{"controls wrong tag", tlv(0x30, bytes.Join([][]byte{tlv(0x02, 0x01), unbindBody, tlv(0xa1)}, nil)...), ErrMalformedPDU},
		{"boolean content too long", tlv(0x30, append(tlv(0x02, 0x01),
			tlv(0x6c, bytes.Join([][]byte{tlv(0x04, 'x'), tlv(0x04, 'y'), tlv(0x01, 0xff, 0xff)}, nil)...)...)...), ErrMalformedPDU},
		{"negative scope enum", tlv(0x30, append(tlv(0x02, 0x01), tlv(0x63, bytes.Join([][]byte{
			tlv(0x04), tlv(0x0a, 0xff), tlv(0x0a, 0x00), tlv(0x02, 0x00), tlv(0x02, 0x00), tlv(0x01, 0x00),
			tlv(0x87, []byte("objectClass")...), tlv(0x30),
		}, nil)...)...)...), ErrMalformedPDU},
		{"deep nesting beyond budget", searchPDU(nestedNot(200)), ErrMalformedPDU},
		{"unknown op tag", tlv(0x30, append(tlv(0x02, 0x01), tlv(0x53)...)...), ErrUnsupportedOp}, // [APPLICATION 19] is unassigned
		{"sasl bind choice", tlv(0x30, append(tlv(0x02, 0x01),
			tlv(0x60, bytes.Join([][]byte{tlv(0x02, 0x03), tlv(0x04), tlv(0xa3)}, nil)...)...)...), ErrUnsupportedOp},
		{"extensible match filter", searchPDU(tlv(0xa9)), ErrUnsupportedOp},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := codec.ReadMessage(context.Background(), bytes.NewReader(tc.pdu))
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

// TestDepthAndElementBudgets pins the budget semantics directly against the
// pre-scan and through the public read path.
func TestDepthAndElementBudgets(t *testing.T) {
	// Within-budget nesting decodes fine through the full path.
	codec := NewBERCodec(BERCodecOptions{})
	msg, err := codec.ReadMessage(context.Background(), bytes.NewReader(searchPDU(nestedNot(30))))
	if err != nil {
		t.Fatalf("30-deep filter must decode: %v", err)
	}
	sr, ok := msg.Op.(*SearchRequest)
	if !ok {
		t.Fatalf("want SearchRequest, got %T", msg.Op)
	}
	depth := 0
	for f := sr.Filter; ; {
		depth++
		n, ok := f.(*FilterNot)
		if !ok {
			break
		}
		f = n.Child
	}
	if depth != 31 { // 30 NOTs + the present leaf
		t.Fatalf("decoded filter depth %d, want 31", depth)
	}

	// Pre-scan budget arithmetic.
	if err := scanTLVs(searchPDU(nestedNot(30)), defaultMaxDepth, defaultMaxElements); err != nil {
		t.Fatalf("scanTLVs 30-deep: %v", err)
	}
	if err := scanTLVs(searchPDU(nestedNot(200)), defaultMaxDepth, defaultMaxElements); !errors.Is(err, ErrMalformedPDU) {
		t.Fatalf("scanTLVs 200-deep: want ErrMalformedPDU, got %v", err)
	}

	// Element budget: many small TLVs, none deep.
	attrs := bytes.Repeat(tlv(0x04), 100) // 100 empty attribute descriptions
	body := bytes.Join([][]byte{
		tlv(0x04), tlv(0x0a, 0x02), tlv(0x0a, 0x00), tlv(0x02, 0x00), tlv(0x02, 0x00), tlv(0x01, 0x00),
		tlv(0x87, []byte("objectClass")...), tlv(0x30, attrs...),
	}, nil)
	pdu := tlv(0x30, append(tlv(0x02, 0x01), tlv(0x63, body...)...)...)
	small := NewBERCodec(BERCodecOptions{MaxPDUBytes: 1 << 20, MaxDepth: 128, MaxElements: 64})
	if _, err := small.ReadMessage(context.Background(), bytes.NewReader(pdu)); !errors.Is(err, ErrMalformedPDU) {
		t.Fatalf("element budget: want ErrMalformedPDU, got %v", err)
	}
	// Same PDU passes with a sufficient budget.
	if _, err := codec.ReadMessage(context.Background(), bytes.NewReader(pdu)); err != nil {
		t.Fatalf("element-rich PDU within budget must decode: %v", err)
	}
}

// TestNonMinimalLength documents the liberal-BER posture: a non-minimal
// long-form length is accepted on read and canonicalized on write.
func TestNonMinimalLengthAccepted(t *testing.T) {
	codec := NewBERCodec(BERCodecOptions{})
	nonMinimal := mustHex(t, "30810c020101600702010304008000") // 0x81 0x0c for 12 bytes
	msg := decodeMsg(t, codec, nonMinimal)
	checkMessagesEqual(t, msg, &Message{ID: 1, Op: &BindRequest{Version: 3}})
	canonical := mustHex(t, "300c020101600702010304008000")
	if enc := encodeMsg(t, codec, msg); !bytes.Equal(enc, canonical) {
		t.Fatalf("re-encode must be canonical:\n got: %x\nwant: %x", enc, canonical)
	}
}

// TestContextCancellation verifies reads and writes honor a canceled context.
func TestContextCancellation(t *testing.T) {
	codec := NewBERCodec(BERCodecOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := codec.ReadMessage(ctx, bytes.NewReader(mustHex(t, "30050201034200"))); !errors.Is(err, context.Canceled) {
		t.Fatalf("read with canceled ctx: want context.Canceled, got %v", err)
	}
	if err := codec.WriteMessage(ctx, io.Discard, &Message{ID: 3, Op: &UnbindRequest{}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("write with canceled ctx: want context.Canceled, got %v", err)
	}
}

// TestStreamFraming reads several messages back-to-back, including through a
// buffering reader (the codec must not over-read past a PDU boundary), and
// expects a clean io.EOF at the end of the stream.
func TestStreamFraming(t *testing.T) {
	codec := NewBERCodec(BERCodecOptions{})
	msgs := []*Message{
		{ID: 1, Op: &BindRequest{Version: 3}},
		{ID: 2, Op: &SearchRequest{BaseDN: "dc=example,dc=test", Filter: &FilterPresent{Attr: "objectClass"}}},
		{ID: 3, Op: &UnbindRequest{}},
	}
	var stream bytes.Buffer
	for _, m := range msgs {
		if err := codec.WriteMessage(context.Background(), &stream, m); err != nil {
			t.Fatal(err)
		}
	}
	r := bufio.NewReader(&stream) // shares a buffer across reads: over-reads would corrupt framing
	for i, want := range msgs {
		got, err := codec.ReadMessage(context.Background(), r)
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		checkMessagesEqual(t, got, want)
	}
	if _, err := codec.ReadMessage(context.Background(), r); !errors.Is(err, io.EOF) {
		t.Fatalf("end of stream: want io.EOF, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// credential hygiene
// ---------------------------------------------------------------------------

// TestBindPasswordRedaction asserts the password never appears in any
// formatting or structured-logging path.
func TestBindPasswordRedaction(t *testing.T) {
	const secret = "test-password"
	br := &BindRequest{Version: 3, Name: "cn=Directory Manager", Password: []byte(secret)}
	outputs := map[string]string{
		"String":     br.String(),
		"GoString":   br.GoString(),
		"%v":         fmt.Sprintf("%v", br),
		"%+v":        fmt.Sprintf("%+v", br),
		"%#v":        fmt.Sprintf("%#v", br),
		"Sprint":     fmt.Sprint(br),
		"msg.String": fmt.Sprintf("%v", &Message{ID: 1, Op: br}),
	}
	var logBuf bytes.Buffer
	slog.New(slog.NewTextHandler(&logBuf, nil)).Info("bind", "op", br)
	outputs["slog"] = logBuf.String()

	for where, out := range outputs {
		if strings.Contains(out, secret) {
			t.Fatalf("%s output leaks password: %q", where, out)
		}
	}
	if !strings.Contains(br.String(), "redacted") {
		t.Fatalf("String() should mark the password as redacted: %q", br.String())
	}
}

// TestErrorMessagesCarryNoCredentials mutates every byte of the simple-bind
// golden and asserts no resulting decode error contains the password or DN.
func TestErrorMessagesCarryNoCredentials(t *testing.T) {
	codec := NewBERCodec(BERCodecOptions{})
	raw := readGolden(t, "bind_request_simple")
	for i := 0; i < len(raw); i++ {
		for _, delta := range []byte{0x01, 0x80, 0xff} {
			mut := bytes.Clone(raw)
			mut[i] ^= delta
			_, err := codec.ReadMessage(context.Background(), bytes.NewReader(mut))
			if err == nil {
				continue
			}
			msg := err.Error()
			if strings.Contains(msg, "test-password") || strings.Contains(msg, "Directory Manager") {
				t.Fatalf("error leaks credential material at byte %d delta %#x: %q", i, delta, msg)
			}
		}
	}
}

// TestZeroSecrets verifies password scrubbing clears the bytes and the field.
func TestZeroSecrets(t *testing.T) {
	pw := []byte("test-password")
	msg := &Message{ID: 1, Op: &BindRequest{Version: 3, Name: "uid=a", Password: pw}}
	ZeroSecrets(msg)
	br := msg.Op.(*BindRequest)
	if br.Password != nil {
		t.Fatalf("Password field must be nil after ZeroSecrets, got %q", br.Password)
	}
	for i, b := range pw {
		if b != 0 {
			t.Fatalf("password byte %d not zeroed", i)
		}
	}
	ZeroSecrets(nil) // must not panic
	ZeroSecrets(&Message{ID: 1, Op: &UnbindRequest{}})
}

// TestPasswordCopiedFromWire mutates the caller's buffer after decoding; the
// message must hold an independent copy (the codec also wipes its own frame
// buffer, so aliasing it would corrupt the credential).
func TestPasswordCopiedFromWire(t *testing.T) {
	codec := NewBERCodec(BERCodecOptions{})
	raw := readGolden(t, "bind_request_simple")
	msg := decodeMsg(t, codec, raw)
	for i := range raw {
		raw[i] = 0
	}
	br := msg.Op.(*BindRequest)
	if string(br.Password) != "test-password" {
		t.Fatalf("decoded password must survive caller buffer mutation, got %q", br.Password)
	}
	ZeroSecrets(msg)
}

// ---------------------------------------------------------------------------
// writer-side behavior
// ---------------------------------------------------------------------------

type failWriter struct{ err error }

func (w failWriter) Write([]byte) (int, error) { return 0, w.err }

type slowWriter struct{ buf bytes.Buffer }

func (w *slowWriter) Write(p []byte) (int, error) { // one byte at a time
	if len(p) == 0 {
		return 0, nil
	}
	return w.buf.Write(p[:1])
}

type unknownTestOp struct{}

func (unknownTestOp) OpCode() OpCode { return OpCode(99) }

func TestWriteMessageErrors(t *testing.T) {
	codec := NewBERCodec(BERCodecOptions{})
	ctx := context.Background()

	if err := codec.WriteMessage(ctx, io.Discard, nil); err == nil {
		t.Fatal("nil message must fail")
	}
	if err := codec.WriteMessage(ctx, io.Discard, &Message{ID: 1}); err == nil {
		t.Fatal("nil operation must fail")
	}
	if err := codec.WriteMessage(ctx, io.Discard, &Message{ID: 1, Op: unknownTestOp{}}); err == nil {
		t.Fatal("unknown operation type must fail")
	}
	for _, id := range []int64{-1, math.MaxInt32 + 1} {
		if err := codec.WriteMessage(ctx, io.Discard, &Message{ID: id, Op: &UnbindRequest{}}); !errors.Is(err, ErrMalformedPDU) {
			t.Fatalf("message id %d: want ErrMalformedPDU, got %v", id, err)
		}
	}

	tiny := NewBERCodec(BERCodecOptions{MaxPDUBytes: 6, MaxDepth: defaultMaxDepth, MaxElements: defaultMaxElements})
	if err := tiny.WriteMessage(ctx, io.Discard, &Message{ID: 3, Op: &UnbindRequest{}}); !errors.Is(err, ErrPDUTooLarge) {
		t.Fatalf("over-limit encode: want ErrPDUTooLarge, got %v", err)
	}

	if err := codec.WriteMessage(ctx, failWriter{err: io.ErrClosedPipe}, &Message{ID: 3, Op: &UnbindRequest{}}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("writer failure must propagate, got %v", err)
	}

	var sw slowWriter
	want := &Message{ID: 3, Op: &UnbindRequest{}}
	if err := codec.WriteMessage(ctx, &sw, want); err != nil {
		t.Fatalf("short-write loop: %v", err)
	}
	if got := decodeMsg(t, codec, sw.buf.Bytes()); !reflect.DeepEqual(got, want) {
		t.Fatalf("short-write loop produced corrupt frame: %#v", got)
	}
}

// TestMaxMessageIDBoundary confirms the full int32 message-ID range encodes
// and decodes.
func TestMaxMessageIDBoundary(t *testing.T) {
	codec := NewBERCodec(BERCodecOptions{})
	want := &Message{ID: math.MaxInt32, Op: &UnbindRequest{}}
	enc := encodeMsg(t, codec, want)
	anchor := mustHex(t, "300802047fffffff4200")
	if !bytes.Equal(enc, anchor) {
		t.Fatalf("max-int32 unbind encoding:\n got: %x\nwant: %x", enc, anchor)
	}
	checkMessagesEqual(t, decodeMsg(t, codec, enc), want)
}

// TestNewBERCodecDefaults verifies zero/negative options fall back to the
// server-limit defaults.
func TestNewBERCodecDefaults(t *testing.T) {
	c := NewBERCodec(BERCodecOptions{})
	if c.MaxPDUBytes() != DefaultLimits().MaxPDUBytes {
		t.Fatalf("default MaxPDUBytes %d, want %d", c.MaxPDUBytes(), DefaultLimits().MaxPDUBytes)
	}
	c = NewBERCodec(BERCodecOptions{MaxPDUBytes: -5, MaxDepth: -1, MaxElements: 0})
	if c.MaxPDUBytes() != DefaultLimits().MaxPDUBytes {
		t.Fatalf("negative MaxPDUBytes must fall back to default, got %d", c.MaxPDUBytes())
	}
	c = NewBERCodec(BERCodecOptions{MaxPDUBytes: 4096})
	if c.MaxPDUBytes() != 4096 {
		t.Fatalf("explicit MaxPDUBytes not honored: %d", c.MaxPDUBytes())
	}
}
