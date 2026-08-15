package ldapserver

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// FuzzDecode is the pre-auth parser fuzz target (T-124). It asserts the core
// invariants on arbitrary input:
//
//   - decoding never panics; malformed input returns an error
//   - any message that decodes re-encodes and re-decodes to itself
//     (decode -> encode -> decode is a fixed point)
//
// The committed seed corpus lives in testdata/fuzz/FuzzDecode (regenerate
// with LABLDAP_GOLDEN_UPDATE=1; fixtures contain no real credentials). The
// golden PDUs are added here as well so the corpus still covers the full
// message model if the seed directory is pruned.
//
// Smoke: go test -fuzz=FuzzDecode -fuzztime=30s ./internal/ldapserver/
func FuzzDecode(f *testing.F) {
	for _, seed := range rawSeeds() {
		f.Add(seed)
	}
	if entries, err := os.ReadDir(goldenDir); err == nil {
		for _, e := range entries {
			data, err := os.ReadFile(filepath.Join(goldenDir, e.Name()))
			if err != nil {
				continue
			}
			if raw, err := hex.DecodeString(strings.TrimSpace(string(data))); err == nil {
				f.Add(raw)
			}
		}
	}

	codec := NewBERCodec(BERCodecOptions{})
	f.Fuzz(func(t *testing.T, data []byte) {
		ctx := context.Background()
		msg, err := codec.ReadMessage(ctx, bytes.NewReader(data))
		if err != nil {
			return // malformed input: any error is acceptable, a panic is not
		}
		var buf bytes.Buffer
		if err := codec.WriteMessage(ctx, &buf, msg); err != nil {
			t.Fatalf("decoded message failed to re-encode: %v", err)
		}
		msg2, err := codec.ReadMessage(ctx, bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatalf("re-encoded message failed to decode: %v", err)
		}
		if !reflect.DeepEqual(msg, msg2) {
			t.Fatalf("decode->encode->decode is not a fixed point:\nfirst:  %#v\nsecond: %#v", msg, msg2)
		}
		ZeroSecrets(msg)
		ZeroSecrets(msg2)
	})
}
