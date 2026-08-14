package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdvertisedFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "architectures.md")
	if err := os.WriteFile(path, []byte("# arches\n\n- linux/amd64\n- linux/arm64\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := advertisedFromFile(path)
	if len(got) != 2 || got[0] != "linux/amd64" || got[1] != "linux/arm64" {
		t.Fatalf("got %v", got)
	}
}

func TestValidateRejectsUnadvertisedMissingUpstream(t *testing.T) {
	err := validate(report{
		UpstreamPlatforms: []string{"linux/amd64"},
		Advertised:        []string{"linux/amd64", "linux/arm64"},
		HostArch:          "amd64",
	})
	if err == nil {
		t.Fatal("expected rejection of advertised arm64")
	}
	if !strings.Contains(err.Error(), "linux/arm64") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidateAcceptsAmd64Only(t *testing.T) {
	if err := validate(report{
		UpstreamPlatforms: []string{"linux/amd64"},
		Advertised:        []string{"linux/amd64"},
		HostArch:          "amd64",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRecordedPlatformsFile(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	got := recordedPlatforms(filepath.Join(root, "deploy", "docker", "dirsrv-platforms.txt"))
	if !contains(got, "linux/amd64") || !contains(got, "linux/arm64") {
		t.Fatalf("recorded platforms = %v", got)
	}
}

func TestRepoArchitecturesFileIsConservative(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	adv := advertisedFromFile(filepath.Join(root, "deploy", "docker", "architectures.md"))
	if !contains(adv, "linux/amd64") {
		t.Fatalf("must advertise linux/amd64, got %v", adv)
	}
	// arm64 may be upstream-present; do not advertise it without a smoke.
	if contains(adv, "linux/arm64") {
		t.Fatal("do not advertise linux/arm64 until an arm64 smoke test is recorded")
	}
}
