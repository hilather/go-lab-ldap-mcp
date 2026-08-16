package ldapserver

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

// FuzzVerifyPassword is the T-149 password-verify fuzz target (parity
// contract C4: stored values may be hostile — a tampered hash must be a
// denial, never a panic or an amplifier). Invariants:
//
//   - verifyPassword never panics and is deterministic
//   - a forged PBKDF2 blob claiming an out-of-budget iteration count is
//     rejected (the decode budget in pwhash.go fails closed)
//   - round-trip: a freshly hashed password verifies; the same hash with a
//     mutated password does not
//
// Smoke: go test -fuzz=FuzzVerifyPassword -fuzztime=30s ./internal/ldapserver/
func FuzzVerifyPassword(f *testing.F) {
	// Seed with representative stored shapes: plaintext, both supported
	// schemes, a 389-spell cleartext, a forged iteration bomb, and
	// truncation/mutation bait. No real credentials.
	h, err := NewStandardHasher(SchemePBKDF2SHA256)
	if err != nil {
		f.Fatal(err)
	}
	h.Iterations = 1000 // fuzz-mode speed; the production default is 210k
	hash, err := h.Hash([]byte("fixture-password"))
	if err != nil {
		f.Fatal(err)
	}
	bomb := make([]byte, 4+16+32)
	binary.BigEndian.PutUint32(bomb, 1<<31) // iteration count far over budget
	for i, s := range bomb {
		bomb[i] = s ^ 0x5a
	}
	bombStored := []byte("{PBKDF2-SHA256}" + base64.StdEncoding.EncodeToString(bomb))
	// The budget gate is asserted directly (not through the fuzz body)
	// because the body cost-caps PBKDF2 work — see fuzzPBKDF2IterCap.
	if verifyPassword(bombStored, []byte("x")) {
		f.Fatal("forged over-budget iteration count was honored")
	}
	edge := make([]byte, 4+16+32)
	binary.BigEndian.PutUint32(edge, maxVerifyIterations+1)
	edgeStored := []byte("{PBKDF2-SHA256}" + base64.StdEncoding.EncodeToString(edge))
	if verifyPassword(edgeStored, []byte("x")) {
		f.Fatal("blob at maxVerifyIterations+1 was honored")
	}
	seeds := [][2][]byte{
		{[]byte("plaintext-fixture"), []byte("plaintext-fixture")},
		{hash, []byte("fixture-password")},
		{hash, []byte("wrong")},
		{[]byte("{SSHA512}" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 64+16))), []byte("x")},
		{[]byte("{CLEARTEXT}fixture-password"), []byte("fixture-password")},
		{[]byte("{PBKDF2-SHA256}" + base64.StdEncoding.EncodeToString(bomb)), []byte("x")},
		{[]byte("{PBKDF2-SHA256}!!!not-base64!!!"), []byte("x")},
		{[]byte("{UNKNOWN-SCHEME}AAAA"), []byte("x")},
		{[]byte("{"), []byte("x")},
		{[]byte("{}"), []byte{}},
		{hash[:len(hash)/2], []byte("fixture-password")},
		{[]byte{}, []byte{}},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, stored, candidate []byte) {
		// Cost cap for the fuzz lane: the production budget
		// (maxVerifyIterations = 4M, ≈2.5s/verify here) exists so real
		// 389-imported hashes verify, but the mutator finds near-cap
		// iteration counts and the coordinator then kills "hung" workers
		// (observed: exit status 2, non-reproducing input). The over-budget
		// rejection is asserted above at setup; under fuzzing, blobs whose
		// declared iteration count exceeds the fuzz cap are skipped — the
		// expensive "expensive but allowed" band is production behavior
		// covered by password_test.go, not a fuzz invariant.
		if fuzzStoredCostly(stored) {
			return
		}
		// Fail-closed and deterministic on arbitrary stored values.
		got := verifyPassword(stored, candidate)
		if again := verifyPassword(stored, candidate); again != got {
			t.Fatalf("verifyPassword not deterministic for stored len %d", len(stored))
		}

		// Round-trip property with a low-iteration hasher: Hash output must
		// verify against the exact password and reject a mutated one.
		hh := &StandardHasher{Scheme: SchemePBKDF2SHA256, Iterations: 1000, Rand: rand.Reader}
		enc, err := hh.Hash(candidate)
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		if !verifyPassword(enc, candidate) {
			t.Fatal("fresh hash did not verify against its password")
		}
		// Mutate by bit-flip, not by appending a NUL: PBKDF2 runs HMAC,
		// which zero-pads short keys to the block size, so "pw" and
		// "pw\x00" are the same key — an append-NUL mutation is a no-op.
		mutated := append([]byte(nil), candidate...)
		if len(mutated) == 0 {
			mutated = []byte("x")
		} else {
			mutated[0] ^= 0xff
		}
		if verifyPassword(enc, mutated) {
			t.Fatal("hash verified against a mutated password")
		}
	})
}

// fuzzPBKDF2IterCap caps PBKDF2 work per fuzz exec (~30ms here), keeping
// thousands of execs/sec so the CI-short lane is meaningful.
const fuzzPBKDF2IterCap = 50_000

// fuzzStoredCostly reports whether stored is a {PBKDF2-SHA256} blob whose
// declared iteration count exceeds the fuzz cap. It reuses the production
// decode path (splitScheme + decodePayload) rather than re-parsing.
func fuzzStoredCostly(stored []byte) bool {
	scheme, payload, ok := splitScheme(stored)
	if !ok || strings.ToUpper(scheme) != SchemePBKDF2SHA256 {
		return false
	}
	raw, ok := decodePayload(payload)
	if !ok || len(raw) < 4 {
		return false
	}
	return binary.BigEndian.Uint32(raw[:4]) > fuzzPBKDF2IterCap
}
