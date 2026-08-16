package store

import (
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver"
)

func TestEntryCodecRoundTrip(t *testing.T) {
	t.Parallel()
	in := &ldapserver.Entry{
		DN: "uid=alice,ou=people,dc=example,dc=test",
		Attributes: []ldapserver.Attribute{
			{Name: "objectClass", Values: [][]byte{[]byte("top"), []byte("person")}},
			{Name: "uid", Values: [][]byte{[]byte("alice")}},
			{Name: "userCertificate;binary", Values: [][]byte{{0x00, 0xff, 0x10}, {}}},
			{Name: "description", Values: [][]byte{}},
		},
	}
	blob, err := encodeEntry(in)
	if err != nil {
		t.Fatalf("encodeEntry: %v", err)
	}
	out, err := decodeEntry(blob)
	if err != nil {
		t.Fatalf("decodeEntry: %v", err)
	}
	if out.DN != in.DN {
		t.Fatalf("DN = %q, want %q", out.DN, in.DN)
	}
	if len(out.Attributes) != len(in.Attributes) {
		t.Fatalf("attrs = %+v", out.Attributes)
	}
	for i, a := range in.Attributes {
		got := out.Attributes[i]
		if got.Name != a.Name || len(got.Values) != len(a.Values) {
			t.Fatalf("attr %d = %+v, want %+v", i, got, a)
		}
		for j, v := range a.Values {
			if !equalBytes(got.Values[j], v) {
				t.Fatalf("attr %d value %d = %v, want %v", i, j, got.Values[j], v)
			}
		}
	}
}

func TestEntryCodecEmptyEntry(t *testing.T) {
	t.Parallel()
	blob, err := encodeEntry(&ldapserver.Entry{DN: "dc=example,dc=test"})
	if err != nil {
		t.Fatalf("encodeEntry: %v", err)
	}
	out, err := decodeEntry(blob)
	if err != nil {
		t.Fatalf("decodeEntry: %v", err)
	}
	if out.DN != "dc=example,dc=test" || len(out.Attributes) != 0 {
		t.Fatalf("decoded = %+v", out)
	}
}

func TestEntryCodecRejectsEmptyAttributeName(t *testing.T) {
	t.Parallel()
	_, err := encodeEntry(&ldapserver.Entry{
		DN:         "dc=example,dc=test",
		Attributes: []ldapserver.Attribute{{Name: "", Values: [][]byte{[]byte("v")}}},
	})
	if err == nil {
		t.Fatal("encodeEntry with empty attribute name must fail")
	}
}

// TestDecodeEntryCorrupt feeds truncated and malformed buffers; decode
// must return an error, never panic.
func TestDecodeEntryCorrupt(t *testing.T) {
	t.Parallel()
	valid, err := encodeEntry(&ldapserver.Entry{
		DN:         "cn=x,dc=example,dc=test",
		Attributes: []ldapserver.Attribute{{Name: "cn", Values: [][]byte{[]byte("x"), []byte("y")}}},
	})
	if err != nil {
		t.Fatalf("encodeEntry: %v", err)
	}
	cases := map[string][]byte{
		"empty":            {},
		"bad version":      {0x7f, 0x00},
		"truncated header": valid[:1],
		"truncated dn":     valid[:3],
		"truncated attrs":  valid[:len(valid)-2],
		"huge attr count":  {entryVersion, 0x01, 'x', 0xff, 0xff, 0xff, 0xff, 0x0f},
		"huge value len":   append(append([]byte{entryVersion, 0x01, 'x', 0x01, 0x02, 'c', 'n', 0x01}, 0xff, 0xff, 0xff, 0xff), 0x0f),
		"trailing junk":    append(append([]byte(nil), valid...), 0x00),
	}
	for name, buf := range cases {
		if _, err := decodeEntry(buf); err == nil {
			t.Errorf("%s: decodeEntry must fail", name)
		}
	}
	// No prefix of a valid encoding may decode successfully.
	for i := 0; i < len(valid); i++ {
		if _, err := decodeEntry(valid[:i]); err == nil {
			t.Errorf("prefix of length %d decoded", i)
		}
	}
	// Error text must not echo stored attribute bytes.
	if _, err := decodeEntry(valid[:len(valid)-1]); err != nil && strings.Contains(err.Error(), "cn=x") {
		t.Errorf("decode error leaks entry content: %v", err)
	}
}
