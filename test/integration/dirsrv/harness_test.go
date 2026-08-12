//go:build integration

package dirsrv

import (
	"strings"
	"testing"
)

func TestPinnedImageStartsAndIsHealthy(t *testing.T) {
	requireDocker(t)
	before, err := runningLabeled()
	if err != nil {
		t.Fatal(err)
	}
	inst := Start(t)
	if inst.LDAPAddr == "" || inst.LDAPSAddr == "" {
		t.Fatal("missing published ports")
	}
	ref, err := ImageRef()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ref, "@sha256:") {
		t.Fatalf("harness pin is not a digest: %s", ref)
	}
	inst.Stop(t)
	after, err := runningLabeled()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) > len(before) {
		t.Fatalf("labeled containers leaked: before=%v after=%v", before, after)
	}
}
