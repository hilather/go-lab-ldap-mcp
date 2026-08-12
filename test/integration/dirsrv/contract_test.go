package dirsrv

import (
	"strings"
	"testing"
)

func TestImageRefIsDigest(t *testing.T) {
	ref, err := ImageRef()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ref, "quay.io/389ds/dirsrv@sha256:") {
		t.Fatalf("unexpected pin %q", ref)
	}
	if strings.Contains(ref, ":latest") {
		t.Fatalf("floating tag in pin: %s", ref)
	}
}
