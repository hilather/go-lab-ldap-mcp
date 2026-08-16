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

// FuzzDecodeStream is the T-149 stream-framing companion to FuzzDecode: the
// server reads a *sequence* of LDAPMessages from one connection, so this
// target fuzzes a concatenation of PDUs plus trailing garbage. Invariants:
//
//   - no panic; the first malformed frame ends the stream with an error
//   - every message read before the error satisfies the same
//     decode -> encode -> decode fixed point as FuzzDecode
//   - framing is self-terminating: the number of decoded messages can never
//     exceed what the input length can hold (a 2-byte minimum frame)
//
// Smoke: go test -fuzz=FuzzDecodeStream -fuzztime=30s ./internal/ldapserver/
func FuzzDecodeStream(f *testing.F) {
	seeds := rawSeeds()
	for _, seed := range seeds {
		f.Add(seed)
	}
	// Two valid messages back to back, then a valid message with garbage
	// appended, to seed the multi-message paths.
	if len(seeds) > 0 {
		var valid []byte
		for _, s := range seeds {
			if _, err := NewBERCodec(BERCodecOptions{}).ReadMessage(context.Background(), bytes.NewReader(s)); err == nil {
				valid = s
				break
			}
		}
		if valid == nil {
			if data, err := os.ReadFile(filepath.Join(goldenDir, "bind_request_anonymous.hex")); err == nil {
				if raw, err := hex.DecodeString(strings.TrimSpace(string(data))); err == nil {
					valid = raw
				}
			}
		}
		if valid != nil {
			f.Add(append(append([]byte(nil), valid...), valid...))
			f.Add(append(append([]byte(nil), valid...), 0x30, 0x03, 0x02, 0x01))
		}
	}

	codec := NewBERCodec(BERCodecOptions{})
	f.Fuzz(func(t *testing.T, data []byte) {
		ctx := context.Background()
		r := bytes.NewReader(data)
		reads := 0
		for {
			msg, err := codec.ReadMessage(ctx, r)
			if err != nil {
				return // stream ends at the first malformed frame
			}
			reads++
			if reads > len(data)/2+1 {
				t.Fatalf("framing did not terminate: %d messages from %d bytes", reads, len(data))
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
				t.Fatalf("stream message not a fixed point:\nfirst:  %#v\nsecond: %#v", msg, msg2)
			}
			ZeroSecrets(msg)
			ZeroSecrets(msg2)
		}
	})
}
