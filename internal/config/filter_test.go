package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
)

func TestParseFilterLimitsAndOverBroad(t *testing.T) {
	t.Parallel()
	if _, err := ParseFilter("", 16, 4096); err == nil || !hasFieldCode(err, "filter", "empty") {
		t.Fatalf("empty: %v", err)
	}
	if _, err := ParseFilterLimits("", 16, 4096); err == nil || !hasFieldCode(err, "filter", "empty") {
		t.Fatalf("empty limits: %v", err)
	}
	if _, err := ParseFilter("(uid="+strings.Repeat("a", 50), 16, 4096); err == nil || !hasFieldCode(err, "filter", "unbalanced") {
		t.Fatalf("unbalanced: %v", err)
	}
	if _, err := ParseFilter("(\x00uid=a)", 16, 4096); err == nil || !hasFieldCode(err, "filter", "invalid") {
		t.Fatalf("nul: %v", err)
	}
	if _, err := ParseFilter(strings.Repeat("(", 20)+strings.Repeat(")", 20), 8, 4096); err == nil || !hasFieldCode(err, "filter", "too_deep") {
		t.Fatalf("too_deep: %v", err)
	}
	if _, err := ParseFilter("(uid="+strings.Repeat("a", 80)+")", 16, 20); err == nil || !hasFieldCode(err, "filter", "too_long") {
		t.Fatalf("too_long: %v", err)
	}
	for _, f := range []string{"(objectClass=*)", "objectClass=*", "*", "(&(objectClass=*))", "(&(objectclass=*))"} {
		if !IsOverBroad(f) {
			t.Fatalf("IsOverBroad(%q) = false", f)
		}
		if _, err := ParseFilter(f, 16, 4096); err == nil || !hasFieldCode(err, "filter", "over_broad") {
			t.Fatalf("ParseFilter match-all %q: %v", f, err)
		}
		if _, err := ParseFilterLimits(f, 16, 4096); err != nil {
			t.Fatalf("ParseFilterLimits must accept match-all %q: %v", f, err)
		}
	}
	if IsOverBroad("(uid=alice)") || IsOverBroad("") {
		t.Fatal("discriminating or empty must not be over-broad")
	}
	got, err := ParseFilter("(uid=alice)", 16, 4096)
	if err != nil || got.Raw != "(uid=alice)" {
		t.Fatalf("ok filter: %v %#v", err, got)
	}
}

func hasFieldCode(err error, path, code string) bool {
	var e *apperr.Error
	if !errors.As(err, &e) {
		return false
	}
	for _, f := range e.Fields() {
		if f.Path == path && f.Code == code {
			return true
		}
	}
	return false
}
