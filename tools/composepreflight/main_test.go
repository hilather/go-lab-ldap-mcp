package main

import "testing"

func TestParseAndCompareVersions(t *testing.T) {
	maj, min, patch, ok := parseVersion("29.1.3-0ubuntu3")
	if !ok || maj != 29 || min != 1 || patch != 3 {
		t.Fatalf("engine parse %d.%d.%d ok=%v", maj, min, patch, ok)
	}
	maj, min, _, ok = parseVersion("v2.40.3+ds1")
	if !ok || maj != 2 || min != 40 {
		t.Fatalf("compose parse %d.%d ok=%v", maj, min, ok)
	}
	if !engineOK("24.0.0") || engineOK("23.9.1") {
		t.Fatal("engine floor")
	}
	if !composeOK("2.24.0") || composeOK("2.23.3") || !composeOK("3.0.0") {
		t.Fatal("compose floor")
	}
}
