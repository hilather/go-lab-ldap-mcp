package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAssertNativeDataDirMissingOK(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "absent")
	if err := AssertNativeDataDir(dir); err != nil {
		t.Fatalf("missing dir: %v", err)
	}
}

func TestAssertNativeDataDirEmptyOK(t *testing.T) {
	t.Parallel()
	if err := AssertNativeDataDir(t.TempDir()); err != nil {
		t.Fatalf("empty dir: %v", err)
	}
}

func TestAssertNativeDataDirRejects389Markers(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "config"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config", "container.inf"), []byte("[slapd]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := AssertNativeDataDir(dir)
	if !errors.Is(err, ErrEngineDataMismatch) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, StoreFileName)); !os.IsNotExist(err) {
		t.Fatal("must not create labldapd.bolt beside 389 files")
	}
}

func TestAssertNativeDataDirRejectsSlapdLayout(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "slapd-localhost"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := AssertNativeDataDir(dir); !errors.Is(err, ErrEngineDataMismatch) {
		t.Fatalf("err = %v", err)
	}
}

func TestAssertNativeDataDirRejectsNonBolt(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, StoreFileName), []byte("not a bolt file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AssertNativeDataDir(dir); !errors.Is(err, ErrEngineDataMismatch) {
		t.Fatalf("err = %v", err)
	}
}

func TestAssertNativeDataDirAcceptsBolt(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, StoreFileName)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := AssertNativeDataDir(dir); err != nil {
		t.Fatalf("valid bolt: %v", err)
	}
}
