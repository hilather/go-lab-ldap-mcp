package directory

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestLDIFHeaderRespectsTinyByteLimit(t *testing.T) {
	for _, closeOnly := range []bool{false, true} {
		var buf bytes.Buffer
		enc := NewEncoder(&buf, ExportOptions{MaxBytes: 1, OmitSecrets: true})
		var err error
		if closeOnly {
			err = enc.Close()
		} else {
			err = enc.WriteEntry(t.Context(), SearchEntry{DN: "dc=test"})
		}
		if err == nil || buf.Len() != 0 {
			t.Fatalf("header bypassed byte cap: bytes=%d err=%v", buf.Len(), err)
		}
	}
}

type nilErrorShortWriter struct{}

func (nilErrorShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
func TestLDIFRejectsShortWriter(t *testing.T) {
	enc := NewEncoder(nilErrorShortWriter{}, ExportOptions{})
	if err := enc.Close(); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write: %v", err)
	}
}
