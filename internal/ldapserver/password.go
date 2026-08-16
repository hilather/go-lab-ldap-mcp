package ldapserver

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// Password policy attributes (389 DS / draft-behera password policy spell;
// parity contract C4).
const (
	attrUserPassword         = "userPassword"
	attrPwdChangedTime       = "pwdChangedTime"
	attrPwdAccountLockedTime = "pwdAccountLockedTime"
	attrPasswordHistory      = "passwordHistory"
)

// Policy rejections on the write path. runPlugins joins these with
// errPlugin; mapWriteError must test them before the generic plugin arm
// so the client sees constraintViolation(19), matching 389 (D18).
var (
	errPasswordTooShort  = errors.New("ldapserver: password below minimum length")
	errPasswordInHistory = errors.New("ldapserver: password present in password history")
)

// PasswordPolicy configures the T-134 policy engine. It is deliberately
// close to config.NormalizedPolicy so cmd/labldapd wiring is a field copy.
//
// Zero values disable each check: MinLength 0 accepts any length,
// HistoryCount 0 keeps no history, MaxAge 0 never expires, MaxFailures 0
// disables lockout. StorageScheme selects the hash-on-write scheme (empty
// is PBKDF2-SHA256). Hasher overrides the scheme-built StandardHasher, and
// Now overrides the clock — both exist for tests.
type PasswordPolicy struct {
	MinLength       int
	HistoryCount    int
	MaxAge          time.Duration
	MaxFailures     int
	LockoutDuration time.Duration
	StorageScheme   string
	Hasher          PasswordHasher
	Now             func() time.Time
}

// validate checks policy coherence. Errors are configuration field errors,
// never panics (AGENTS.md); paths are relative to "passwordPolicy".
func (p PasswordPolicy) validate() error {
	var fields []apperr.Field
	if p.MinLength < 0 {
		fields = append(fields, apperr.Field{Path: "passwordPolicy.minLength", Code: "invalid_policy", Message: "minLength cannot be negative"})
	}
	if p.HistoryCount < 0 {
		fields = append(fields, apperr.Field{Path: "passwordPolicy.historyCount", Code: "invalid_policy", Message: "historyCount cannot be negative"})
	}
	if p.MaxAge < 0 {
		fields = append(fields, apperr.Field{Path: "passwordPolicy.maxAge", Code: "invalid_policy", Message: "maxAge cannot be negative"})
	}
	if p.MaxFailures < 0 {
		fields = append(fields, apperr.Field{Path: "passwordPolicy.maxFailures", Code: "invalid_policy", Message: "maxFailures cannot be negative"})
	}
	if p.MaxFailures > 0 && p.LockoutDuration < 0 {
		fields = append(fields, apperr.Field{Path: "passwordPolicy.lockoutDuration", Code: "invalid_policy", Message: "lockoutDuration cannot be negative"})
	}
	if p.Hasher == nil {
		if _, err := normalizeScheme(p.StorageScheme); err != nil {
			fields = append(fields, apperr.Field{Path: "passwordPolicy.storageScheme", Code: "invalid_scheme", Message: err.Error()})
		}
	}
	if len(fields) > 0 {
		return apperr.New(apperr.CodeConfiguration, "ldapserver: invalid password policy").WithFields(fields...)
	}
	return nil
}

// passwordEngine is the T-134 policy engine: it verifies binds against
// hashed userPassword values (VerifyBind, called from the Server.passwordGate
// seam) and enforces write-path policy as a Plugin (hash-on-write, minimum
// length, history, pwdChangedTime). Bind-failure counts live in memory;
// lockout state that must survive inspection is written to the entry as
// pwdAccountLockedTime (C4). The engine never logs passwords or hashes.
type passwordEngine struct {
	policy PasswordPolicy
	hasher PasswordHasher
	now    func() time.Time
	logger *slog.Logger

	mu       sync.Mutex
	failures map[string]int
}

func newPasswordEngine(p PasswordPolicy, logger *slog.Logger) (*passwordEngine, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	hasher := p.Hasher
	if hasher == nil {
		h, err := NewStandardHasher(p.StorageScheme)
		if err != nil {
			return nil, err
		}
		hasher = h
	}
	now := p.Now
	if now == nil {
		now = time.Now
	}
	return &passwordEngine{
		policy:   p,
		hasher:   hasher,
		now:      now,
		logger:   logger,
		failures: map[string]int{},
	}, nil
}

// Name implements Plugin.
func (e *passwordEngine) Name() string { return "pwpolicy" }

// VerifyBind is the bind-path half of the policy engine (C4): lockout
// check, scheme-aware password verification, maximum-age check, and the
// failure counter / pwdAccountLockedTime bookkeeping. Unknown user and
// wrong password are indistinguishable upstream (the bind path resolves
// the entry), and locked or expired accounts return the same
// invalidCredentials(49) 389 is observed to return from the management API
// (bind-code parity is a Delta candidate for the T-147 oracle).
func (e *passwordEngine) VerifyBind(ctx context.Context, store Store, dn config.DN, entry *Entry, password []byte) (Result, bool) {
	invalid := Result{Code: ResultInvalidCredentials, DiagnosticMessage: "invalid credentials"}
	key := dn.FoldedKey()
	now := e.now().UTC()

	lockEnabled := e.policy.MaxFailures > 0
	lockPresent := false
	if lockEnabled {
		lockedAt, present, ok := generalizedTimeAttr(entry, attrPwdAccountLockedTime)
		if !ok {
			// Security state that cannot be parsed fails closed; the DN is
			// logged but never the malformed value.
			e.logger.LogAttrs(ctx, slog.LevelWarn, "unparseable pwdAccountLockedTime; failing closed",
				slog.String("dn", dn.String()))
			return invalid, false
		}
		lockPresent = present
		if present && e.lockHeld(lockedAt, now) {
			e.logger.LogAttrs(ctx, slog.LevelInfo, "bind rejected: account locked", slog.String("dn", dn.String()))
			return invalid, false
		}
	}

	matched := false
	for _, v := range entry.Values(attrUserPassword) {
		if e.hasher.Verify(v, password) {
			matched = true
			break
		}
	}
	if !matched {
		if lockEnabled {
			e.recordFailure(ctx, store, key, dn, now)
		}
		return invalid, false
	}

	if e.policy.MaxAge > 0 {
		changedAt, present, ok := generalizedTimeAttr(entry, attrPwdChangedTime)
		if !ok {
			e.logger.LogAttrs(ctx, slog.LevelWarn, "unparseable pwdChangedTime; failing closed",
				slog.String("dn", dn.String()))
			return invalid, false
		}
		if present && now.Sub(changedAt) > e.policy.MaxAge {
			return Result{Code: ResultInvalidCredentials, DiagnosticMessage: "password expired"}, false
		}
	}

	if lockEnabled {
		e.mu.Lock()
		delete(e.failures, key)
		e.mu.Unlock()
		if lockPresent {
			// The lock window elapsed: clear the attribute so the account
			// no longer reports locked (389 clears on successful bind).
			e.writeLockAttr(ctx, store, dn, nil)
		}
	}
	return Result{Code: ResultSuccess}, true
}

// lockHeld reports whether a lock stamped at lockedAt still applies at now.
// A non-positive LockoutDuration is a permanent lock (389 semantics: the
// account stays locked until an administrator removes the attribute).
func (e *passwordEngine) lockHeld(lockedAt, now time.Time) bool {
	if e.policy.LockoutDuration <= 0 {
		return true
	}
	return now.Before(lockedAt.Add(e.policy.LockoutDuration))
}

// recordFailure counts one bind failure and, at the threshold, stamps
// pwdAccountLockedTime on the entry. The counter resets on lock so the
// post-unlock window starts clean. A failed lock write only logs — the
// bind already failed and the in-memory count still gates.
func (e *passwordEngine) recordFailure(ctx context.Context, store Store, key string, dn config.DN, now time.Time) {
	e.mu.Lock()
	e.failures[key]++
	n := e.failures[key]
	if n >= e.policy.MaxFailures {
		delete(e.failures, key)
	}
	e.mu.Unlock()
	if n < e.policy.MaxFailures {
		return
	}
	e.logger.LogAttrs(ctx, slog.LevelInfo, "account locked after bind failures",
		slog.String("dn", dn.String()), slog.Int("failures", n))
	e.writeLockAttr(ctx, store, dn, &now)
}

// writeLockAttr sets (at non-nil) or removes (at nil) pwdAccountLockedTime
// through one store transaction. Errors are logged, not surfaced: the bind
// result must not depend on bookkeeping writes.
func (e *passwordEngine) writeLockAttr(ctx context.Context, store Store, dn config.DN, at *time.Time) {
	err := store.Update(ctx, func(tx UpdateTx) error {
		cur, err := tx.Entry(ctx, dn)
		if err != nil {
			return err
		}
		if at != nil {
			upsertAttr(cur, attrPwdAccountLockedTime, formatGeneralizedTime(*at))
		} else if !removeAttr(cur, attrPwdAccountLockedTime) {
			return nil
		}
		return tx.Replace(ctx, cur)
	})
	if err != nil {
		e.logger.LogAttrs(ctx, slog.LevelError, "failed to update pwdAccountLockedTime",
			slog.String("dn", dn.String()), slog.String("error", err.Error()))
	}
}

// AfterWrite implements Plugin. Password policy lives on Add and Modify;
// deletes and renames do not touch credentials. The entry is always
// re-read inside the transaction so earlier plugins' changes are preserved
// (pwpolicy is registered last by New; every plugin must re-read before
// Replace to avoid clobbering).
func (e *passwordEngine) AfterWrite(ctx context.Context, tx UpdateTx, ev WriteEvent) error {
	switch ev.Op {
	case WriteAdd:
		if ev.After == nil {
			return nil
		}
		return e.applyAdd(ctx, tx, ev.After)
	case WriteModify:
		if ev.Before == nil || ev.After == nil {
			return nil
		}
		return e.applyModify(ctx, tx, ev.Before, ev.After, ev.Subject)
	default:
		return nil
	}
}

// applyAdd hashes plaintext userPassword values and stamps pwdChangedTime.
// Pre-hashed values pass through untouched (the import/seed seam, Delta D3).
func (e *passwordEngine) applyAdd(ctx context.Context, tx UpdateTx, after *Entry) error {
	vals := after.Values(attrUserPassword)
	if len(vals) == 0 {
		return nil
	}
	dn, err := config.ParseDN(after.DN)
	if err != nil {
		return fmt.Errorf("ldapserver: pwpolicy add: %w", err)
	}
	out := make([][]byte, 0, len(vals))
	for _, v := range vals {
		if isPreHashed(v) {
			out = append(out, append([]byte(nil), v...))
			continue
		}
		if err := e.checkNewPassword(v, nil); err != nil {
			return err
		}
		hashed, err := e.hasher.Hash(v)
		if err != nil {
			return fmt.Errorf("ldapserver: pwpolicy hash on add: %w", err)
		}
		out = append(out, hashed)
	}
	cur, err := tx.Entry(ctx, dn)
	if err != nil {
		return fmt.Errorf("ldapserver: pwpolicy add re-read: %w", err)
	}
	setAttrValues(cur, attrUserPassword, out)
	upsertAttr(cur, attrPwdChangedTime, formatGeneralizedTime(e.now()))
	return tx.Replace(ctx, cur)
}

// applyModify enforces policy when the modification touched userPassword:
// minimum length and history are checked against plaintext values, then
// values are hashed, pwdChangedTime is stamped, and the previous passwords
// move into passwordHistory (trimmed to HistoryCount). A pre-hashed value
// passes through without checks — imports carry already-hashed blobs whose
// plaintext cannot be validated. Directory Manager (BypassACI) skips the
// history check so seed merge / soft-reset can re-apply a secret that is
// already in history (D29); minimum length still applies.
func (e *passwordEngine) applyModify(ctx context.Context, tx UpdateTx, before, after *Entry, subj Subject) error {
	beforeVals := before.Values(attrUserPassword)
	afterVals := after.Values(attrUserPassword)
	if sameByteSet(beforeVals, afterVals) {
		return nil
	}
	dn, err := config.ParseDN(after.DN)
	if err != nil {
		return fmt.Errorf("ldapserver: pwpolicy modify: %w", err)
	}
	cur, err := tx.Entry(ctx, dn)
	if err != nil {
		return fmt.Errorf("ldapserver: pwpolicy modify re-read: %w", err)
	}
	if len(afterVals) == 0 {
		// Password removed: drop the policy timestamps; history stays so a
		// later re-add cannot immediately reuse an old password.
		if removeAttr(cur, attrPwdChangedTime) {
			return tx.Replace(ctx, cur)
		}
		return nil
	}

	// History inputs: the recorded history plus the current values, which
	// become history on success — so re-setting the current password is
	// also rejected (389 CAND-11). DM BypassACI skips the check entirely.
	var history [][]byte
	if !subj.BypassACI {
		history = append([][]byte(nil), cur.Values(attrPasswordHistory)...)
		history = append(history, beforeVals...)
	}
	out := make([][]byte, 0, len(afterVals))
	for _, v := range afterVals {
		if isPreHashed(v) {
			out = append(out, append([]byte(nil), v...))
			continue
		}
		if err := e.checkNewPassword(v, history); err != nil {
			return err
		}
		hashed, err := e.hasher.Hash(v)
		if err != nil {
			return fmt.Errorf("ldapserver: pwpolicy hash on modify: %w", err)
		}
		out = append(out, hashed)
	}
	setAttrValues(cur, attrUserPassword, out)
	upsertAttr(cur, attrPwdChangedTime, formatGeneralizedTime(e.now()))
	if e.policy.HistoryCount > 0 {
		var prior [][]byte
		for _, v := range beforeVals {
			if isPreHashed(v) {
				prior = append(prior, append([]byte(nil), v...))
				continue
			}
			hashed, err := e.hasher.Hash(v)
			if err != nil {
				return fmt.Errorf("ldapserver: pwpolicy history hash: %w", err)
			}
			prior = append(prior, hashed)
		}
		hist := append(prior, cur.Values(attrPasswordHistory)...)
		if len(hist) > e.policy.HistoryCount {
			hist = hist[:e.policy.HistoryCount]
		}
		setAttrValues(cur, attrPasswordHistory, hist)
	}
	return tx.Replace(ctx, cur)
}

// checkNewPassword enforces minimum length (bytes, as 389 counts) and
// history on one plaintext candidate. Constant-time verification inside
// verifyPassword keeps history checks from becoming a timing oracle.
func (e *passwordEngine) checkNewPassword(plaintext []byte, history [][]byte) error {
	if e.policy.MinLength > 0 && len(plaintext) < e.policy.MinLength {
		return errPasswordTooShort
	}
	if e.policy.HistoryCount > 0 {
		for _, h := range history {
			if e.hasher.Verify(h, plaintext) {
				return errPasswordInHistory
			}
		}
	}
	return nil
}

// passwordGate is the T-134 bind-path seam: op_bind.go calls exactly this
// after resolving the entry. Without a configured policy it preserves the
// T-126 behavior (constant-time plaintext compare, no state). With a
// policy it delegates to the engine. The constant-time discipline is kept
// by the hasher in both modes; passwords never cross the log boundary.
func (s *Server) passwordGate(ctx context.Context, dn config.DN, entry *Entry, password []byte) (Result, bool) {
	if s.passwords == nil {
		for _, v := range entry.Values(attrUserPassword) {
			if subtle.ConstantTimeCompare(v, password) == 1 {
				return Result{Code: ResultSuccess}, true
			}
		}
		return Result{Code: ResultInvalidCredentials, DiagnosticMessage: "invalid credentials"}, false
	}
	return s.passwords.VerifyBind(ctx, s.opts.Store, dn, entry, password)
}

// generalizedTimeAttr reads one GeneralizedTime attribute. ok is false when
// the value is present but unparseable; present is false when absent or
// empty. Only UTC "Z" spellings and optional fractional seconds are
// accepted, which is what the engine itself writes.
func generalizedTimeAttr(e *Entry, name string) (t time.Time, present, ok bool) {
	vals := e.Values(name)
	if len(vals) == 0 || len(vals[0]) == 0 {
		return time.Time{}, false, true
	}
	parsed, err := parseGeneralizedTime(string(vals[0]))
	if err != nil {
		return time.Time{}, true, false
	}
	return parsed, true, true
}

func formatGeneralizedTime(t time.Time) string {
	return t.UTC().Format("20060102150405Z")
}

func parseGeneralizedTime(s string) (time.Time, error) {
	for _, layout := range []string{"20060102150405Z", "20060102150405.999999999Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("ldapserver: invalid generalized time")
}

// upsertAttr replaces or appends a single-valued attribute.
func upsertAttr(e *Entry, name, value string) {
	for i, a := range e.Attributes {
		if strings.EqualFold(a.Name, name) {
			e.Attributes[i].Values = [][]byte{[]byte(value)}
			return
		}
	}
	e.Attributes = append(e.Attributes, Attribute{Name: name, Values: [][]byte{[]byte(value)}})
}

// setAttrValues replaces or appends a multi-valued attribute.
func setAttrValues(e *Entry, name string, values [][]byte) {
	for i, a := range e.Attributes {
		if strings.EqualFold(a.Name, name) {
			e.Attributes[i].Values = values
			return
		}
	}
	e.Attributes = append(e.Attributes, Attribute{Name: name, Values: values})
}

// removeAttr deletes an attribute, reporting whether it existed.
func removeAttr(e *Entry, name string) bool {
	for i, a := range e.Attributes {
		if strings.EqualFold(a.Name, name) {
			e.Attributes = append(e.Attributes[:i], e.Attributes[i+1:]...)
			return true
		}
	}
	return false
}

// sameByteSet reports whether two value lists hold the same bytes,
// order-insensitively.
func sameByteSet(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	used := make([]bool, len(b))
outer:
	for _, x := range a {
		for i, y := range b {
			if !used[i] && bytes.Equal(x, y) {
				used[i] = true
				continue outer
			}
		}
		return false
	}
	return true
}
