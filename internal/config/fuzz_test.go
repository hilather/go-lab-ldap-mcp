package config

import (
	"strings"
	"testing"
)

func FuzzParseYAML(f *testing.F) {
	f.Add([]byte("apiVersion: labldap.dev/v1alpha1\nkind: LabScenario\nmetadata:\n  name: x\nspec: {}\n"))
	f.Fuzz(func(t *testing.T, in []byte) {
		_, _ = Parse(in, "fuzz.yaml")
	})
}

func FuzzParseDN(f *testing.F) {
	f.Add("uid=alice,ou=people,dc=example,dc=test")
	f.Add(`cn=foo\,bar,dc=ex`)
	f.Fuzz(func(t *testing.T, in string) {
		_, _ = ParseDN(in)
	})
}

func FuzzParseFilter(f *testing.F) {
	f.Add("(uid=alice)")
	f.Add("(objectClass=*)")
	f.Fuzz(func(t *testing.T, in string) {
		_, _ = ParseFilter(in, 16, 4096)
	})
}

func FuzzACIEscape(f *testing.F) {
	f.Add(`evil")(cn=config`)
	f.Fuzz(func(t *testing.T, in string) {
		out := aciEscape(in)
		if strings.Contains(out, `")(`) {
			t.Fatalf("unescaped injection: %q -> %q", in, out)
		}
	})
}

func FuzzCursor(f *testing.F) {
	f.Add([]byte("uid=alice"))
	f.Fuzz(func(t *testing.T, in []byte) {
		s, err := EncodeCursor(Cursor{Query: string(in), Page: "0"})
		if err != nil {
			return
		}
		_, _ = DecodeCursor(s)
		_, _ = DecodeCursor(string(in))
	})
}
