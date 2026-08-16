package ldapserver

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

func TestStandardHasherRoundTrip(t *testing.T) {
	t.Parallel()
	for _, scheme := range []string{SchemePBKDF2SHA256, SchemeSSHA512} {
		t.Run(scheme, func(t *testing.T) {
			t.Parallel()
			h, err := NewStandardHasher(scheme)
			if err != nil {
				t.Fatalf("NewStandardHasher: %v", err)
			}
			h.Iterations = 1_000 // test speed; format is iteration-agnostic
			stored, err := h.Hash([]byte("correct horse battery staple"))
			if err != nil {
				t.Fatalf("Hash: %v", err)
			}
			if !strings.HasPrefix(string(stored), "{"+scheme+"}") {
				t.Fatalf("stored = %q, want {%s} prefix", stored, scheme)
			}
			if strings.Contains(string(stored), "correct horse") {
				t.Fatal("stored value echoes the plaintext password")
			}
			if !h.Verify(stored, []byte("correct horse battery staple")) {
				t.Fatal("Verify rejected the correct password")
			}
			if h.Verify(stored, []byte("correct horse battery staple2")) {
				t.Fatal("Verify accepted a wrong password")
			}
			if h.Verify(stored, nil) {
				t.Fatal("Verify accepted an empty password")
			}
		})
	}
}

func TestHasherSaltRandomized(t *testing.T) {
	t.Parallel()
	h, err := NewStandardHasher(SchemeSSHA512)
	if err != nil {
		t.Fatalf("NewStandardHasher: %v", err)
	}
	a, err := h.Hash([]byte("same-password"))
	if err != nil {
		t.Fatalf("Hash a: %v", err)
	}
	b, err := h.Hash([]byte("same-password"))
	if err != nil {
		t.Fatalf("Hash b: %v", err)
	}
	if string(a) == string(b) {
		t.Fatal("two hashes of one password are byte-identical; salt is not random")
	}
	if !h.Verify(a, []byte("same-password")) || !h.Verify(b, []byte("same-password")) {
		t.Fatal("salted hashes do not verify")
	}
}

func TestSchemeNormalization(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"":              SchemePBKDF2SHA256,
		"PBKDF2-SHA256": SchemePBKDF2SHA256,
		"PBKDF2_SHA256": SchemePBKDF2SHA256, // config-file alias (v1alpha1)
		"pbkdf2-sha256": SchemePBKDF2SHA256,
		"SSHA512":       SchemeSSHA512,
		"ssha512":       SchemeSSHA512,
	} {
		got, err := normalizeScheme(in)
		if err != nil {
			t.Fatalf("normalizeScheme(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("normalizeScheme(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := NewStandardHasher("MD5"); err == nil {
		t.Fatal("NewStandardHasher(MD5) succeeded; want failure")
	}
}

func TestVerifyCrossSchemeAndFallbacks(t *testing.T) {
	t.Parallel()
	h, err := NewStandardHasher(SchemePBKDF2SHA256)
	if err != nil {
		t.Fatalf("NewStandardHasher: %v", err)
	}
	h.Iterations = 1_000
	pbkdfStored, err := h.Hash([]byte("pw"))
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	// Verification is scheme-aware from the prefix: an SSHA512-configured
	// hasher still verifies a PBKDF2 blob (mixed imports).
	sshaHasher, err := NewStandardHasher(SchemeSSHA512)
	if err != nil {
		t.Fatalf("NewStandardHasher: %v", err)
	}
	if !sshaHasher.Verify(pbkdfStored, []byte("pw")) {
		t.Fatal("cross-scheme verify failed")
	}

	cases := []struct {
		name   string
		stored string
		want   bool
	}{
		{"plaintext fallback", "alice-fixture-password", true},
		{"cleartext scheme", "{CLEARTEXT}pw", false}, // password is "pw"... see below
		{"unknown scheme fails closed", "{MD5}cHc=", false},
		{"empty stored", "", false},
		{"garbage prefix", "{PBKDF2-SHA256}!!!not-base64!!!", false},
		{"truncated blob", "{SSHA512}" + base64.StdEncoding.EncodeToString([]byte("short")), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := h.Verify([]byte(tc.stored), []byte("alice-fixture-password"))
			if tc.name == "cleartext scheme" {
				got = h.Verify([]byte(tc.stored), []byte("pw"))
				if !got {
					t.Fatal("{CLEARTEXT}pw did not verify against pw")
				}
				return
			}
			if got != tc.want {
				t.Fatalf("Verify(%q) = %v, want %v", tc.stored, got, tc.want)
			}
		})
	}
}

// TestVerifyPBKDF2IterationCeiling proves a forged blob cannot turn
// verification into a CPU amplifier: an out-of-bounds iteration count is
// rejected before any derivation.
func TestVerifyPBKDF2IterationCeiling(t *testing.T) {
	t.Parallel()
	h, err := NewStandardHasher(SchemePBKDF2SHA256)
	if err != nil {
		t.Fatalf("NewStandardHasher: %v", err)
	}
	payload := make([]byte, 4, 4+pbkdf2SaltBytes+pbkdf2KeyBytes)
	binary.BigEndian.PutUint32(payload, maxVerifyIterations+1)
	payload = append(payload, make([]byte, pbkdf2SaltBytes+pbkdf2KeyBytes)...)
	forged := encodePrefixed(SchemePBKDF2SHA256, payload)
	if h.Verify(forged, []byte("pw")) {
		t.Fatal("forged over-ceiling iteration count verified")
	}
	// Zero iterations is equally bogus.
	binary.BigEndian.PutUint32(payload, 0)
	if h.Verify(encodePrefixed(SchemePBKDF2SHA256, payload), []byte("pw")) {
		t.Fatal("zero-iteration blob verified")
	}
}

// TestVerifyRejectsOversizedBlob guards the pre-decode size ceiling.
func TestVerifyRejectsOversizedBlob(t *testing.T) {
	t.Parallel()
	h, err := NewStandardHasher(SchemeSSHA512)
	if err != nil {
		t.Fatalf("NewStandardHasher: %v", err)
	}
	huge := strings.Repeat("A", maxStoredPasswordBytes+1)
	if h.Verify([]byte(huge), []byte("pw")) {
		t.Fatal("oversized stored value verified")
	}
}
