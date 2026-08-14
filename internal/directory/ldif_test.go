package directory

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
)

func TestLDIFRoundTripIndependentParser(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("abcdefghijklmnopqrstuvwxyz ", 8)
	entries := []SearchEntry{
		{
			DN: "uid=alice,ou=people,dc=example,dc=test",
			Attributes: []AttrKV{
				{Name: "sn", Value: "Example"},
				{Name: "objectClass", Value: "inetOrgPerson"},
				{Name: "objectClass", Value: "person"},
				{Name: "cn", Value: "Alice Example"},
				{Name: "userPassword", Value: "unit-ldif-secret-12"},
				{Name: "uid", Value: "alice"},
			},
		},
		{
			DN: "cn=weird,dc=example,dc=test",
			Attributes: []AttrKV{
				{Name: "description", Value: " starts with space"},
				{Name: "cn", Value: "weird"},
				{Name: "note", Value: "colon: value and 日本語"},
				{Name: "objectClass", Value: "top"},
			},
		},
		{
			DN: "cn=fold,dc=example,dc=test",
			Attributes: []AttrKV{
				{Name: "description", Value: long},
				{Name: "cn", Value: "fold"},
			},
		},
	}
	var buf bytes.Buffer
	enc := NewEncoder(&buf, ExportOptions{OmitSecrets: true})
	for _, e := range entries {
		if err := enc.WriteEntry(t.Context(), e); err != nil {
			t.Fatal(err)
		}
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	raw := buf.String()
	if strings.Contains(raw, "unit-ldif-secret-12") || strings.Contains(strings.ToLower(raw), "userpassword") {
		t.Fatalf("secret leaked:\n%s", raw)
	}
	if !strings.Contains(raw, "version: 1") || !strings.Contains(raw, LDIFCompleteMark) {
		t.Fatalf("header/trailer missing:\n%s", raw)
	}
	got, err := ParseLDIF(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("entries %d\n%s", len(got), raw)
	}
	if got[0].DN != entries[0].DN || attrOf(got[0], "sn") != "Example" || attrOf(got[0], "uid") != "alice" {
		t.Fatalf("alice %+v", got[0])
	}
	if attrOf(got[1], "description") != " starts with space" || attrOf(got[1], "note") != "colon: value and 日本語" {
		t.Fatalf("weird %+v\n%s", got[1], raw)
	}
	if attrOf(got[2], "description") != long {
		t.Fatalf("fold mismatch:\n%s", raw)
	}
	if !strings.Contains(raw, "\n ") {
		t.Fatalf("expected folded line:\n%s", raw)
	}
}

func TestLDIFTrailingSpaceUsesBase64(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	enc := NewEncoder(&buf, ExportOptions{OmitSecrets: true})
	if err := enc.WriteEntry(t.Context(), SearchEntry{
		DN:         "cn=pad,dc=example,dc=test",
		Attributes: []AttrKV{{Name: "description", Value: "ends with "}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	raw := buf.String()
	if !strings.Contains(raw, "description:: ") {
		t.Fatalf("expected base64 trailing space:\n%s", raw)
	}
	if strings.Contains(raw, "description: ends with ") {
		t.Fatalf("unsafe trailing space:\n%s", raw)
	}
	got, err := ParseLDIF(strings.NewReader(raw))
	if err != nil || len(got) != 1 || attrOf(got[0], "description") != "ends with " {
		t.Fatalf("round-trip %+v %v\n%s", got, err, raw)
	}
}

func TestLDIFEncoderOmitsSecretsAndStreams(t *testing.T) {
	t.Parallel()
	var writes int
	w := writerFunc(func(p []byte) (int, error) {
		writes++
		return len(p), nil
	})
	enc := NewEncoder(w, ExportOptions{OmitSecrets: true})
	if err := enc.WriteEntry(t.Context(), SearchEntry{
		DN: "uid=a,dc=example,dc=test",
		Attributes: []AttrKV{
			{Name: "userPassword", Value: "unit-ldif-secret-12"},
			{Name: "authPassword", Value: "unit-ldif-secret-12"},
			{Name: "cn", Value: "a"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if writes == 0 {
		t.Fatal("encoder buffered the entry instead of writing")
	}
	if enc.Entries() != 1 {
		t.Fatalf("entries %d", enc.Entries())
	}
}

func TestLDIFEncoderHonorsCancelAndLimits(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	enc := NewEncoder(io.Discard, ExportOptions{OmitSecrets: true})
	if err := enc.WriteEntry(ctx, SearchEntry{DN: "cn=x,dc=example,dc=test"}); err == nil {
		t.Fatal("canceled")
	}

	limited := NewEncoder(io.Discard, ExportOptions{OmitSecrets: true, MaxEntries: 1})
	e := SearchEntry{DN: "cn=x,dc=example,dc=test", Attributes: []AttrKV{{Name: "cn", Value: "x"}}}
	if err := limited.WriteEntry(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	err := limited.WriteEntry(t.Context(), SearchEntry{DN: "cn=y,dc=example,dc=test"})
	if err == nil {
		t.Fatal("entry limit")
	}
	if apperr.CodeOf(err) != apperr.CodeExport {
		t.Fatalf("code %v", err)
	}

	tiny := NewEncoder(io.Discard, ExportOptions{OmitSecrets: true, MaxBytes: 20})
	if err := tiny.WriteEntry(t.Context(), SearchEntry{
		DN:         "cn=toolong,dc=example,dc=test",
		Attributes: []AttrKV{{Name: "description", Value: strings.Repeat("z", 80)}},
	}); err == nil {
		t.Fatal("byte limit")
	}
}

func TestLDIFDeterministicOrder(t *testing.T) {
	t.Parallel()
	var a, b bytes.Buffer
	in := SearchEntry{
		DN: "uid=z,dc=example,dc=test",
		Attributes: []AttrKV{
			{Name: "sn", Value: "Z"},
			{Name: "cn", Value: "b"},
			{Name: "cn", Value: "a"},
			{Name: "objectClass", Value: "person"},
		},
	}
	for _, w := range []*bytes.Buffer{&a, &b} {
		enc := NewEncoder(w, ExportOptions{OmitSecrets: true})
		if err := enc.WriteEntry(t.Context(), in); err != nil {
			t.Fatal(err)
		}
		if err := enc.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if a.String() != b.String() {
		t.Fatalf("nondeterministic\n%s\n---\n%s", a.String(), b.String())
	}
	body := a.String()
	cn := strings.Index(body, "cn: a")
	cn2 := strings.Index(body, "cn: b")
	oc := strings.Index(body, "objectclass: person")
	sn := strings.Index(body, "sn: Z")
	if cn < 0 || cn2 < 0 || oc < 0 || sn < 0 || !(cn < cn2 && cn2 < oc && oc < sn) {
		t.Fatalf("attr order:\n%s", body)
	}
}

func attrOf(e SearchEntry, name string) string {
	want := strings.ToLower(name)
	for _, a := range e.Attributes {
		if strings.ToLower(a.Name) == want {
			return a.Value
		}
	}
	return ""
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
