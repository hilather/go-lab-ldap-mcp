package apperr

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// EqualGolden compares got to testdata/<name>. Update with UPDATE_GOLDEN=1.
func EqualGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v", path, err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("golden %s mismatch\nwant:\n%s\ngot:\n%s", name, want, got)
	}
}
