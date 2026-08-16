package ldapserver

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// pagedOptions seeds a suffix, ou=people, and exactly five person entries
// for the T-140 acceptance walk (page size 2 → pages of 2, 2, 1).
func pagedOptions(t *testing.T) Options {
	t.Helper()
	opts := testOptions()
	opts.Codec = NewBERCodec(BERCodecOptions{})
	opts.Schema = searchSchema()
	opts.ACI = &FakeACI{Decide: func(ctx context.Context, tx ReadTx, check ACICheck) (bool, error) {
		return true, nil
	}}
	ctx := context.Background()
	err := opts.Store.Update(ctx, func(tx UpdateTx) error {
		if err := tx.Add(ctx, NewEntry("dc=example,dc=test",
			StringAttribute("objectClass", "top", "domain"))); err != nil {
			return err
		}
		if err := tx.Add(ctx, NewEntry("ou=people,dc=example,dc=test",
			StringAttribute("objectClass", "top", "organizationalUnit"),
			StringAttribute("ou", "people"))); err != nil {
			return err
		}
		for i := 1; i <= 5; i++ {
			name := fmt.Sprintf("user%d", i)
			if err := tx.Add(ctx, NewEntry("uid="+name+",ou=people,dc=example,dc=test",
				StringAttribute("objectClass", "top", "person"),
				StringAttribute("uid", name),
				StringAttribute("cn", name),
				StringAttribute("sn", name))); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	return opts
}

// pagedPage issues one paged one-level search over the five seeded users
// and returns the page entries, the done result, and the response cookie.
func pagedPage(t *testing.T, cl *ldapTestClient, cookie []byte) ([]*SearchResultEntry, *SearchResultDone, []byte) {
	t.Helper()
	ctrl := Control{OID: OIDSimplePagedResults, Value: encodePagedCookie(2, cookie)}
	entries, done, respControls := searchFull(t, cl, &SearchRequest{
		BaseDN: "ou=people,dc=example,dc=test", Scope: ScopeSingleLevel,
		Filter: &FilterPresent{Attr: "objectClass"},
	}, ctrl)
	return entries, done, decodePagedCookie(t, respControls)
}

// TestPagedResultsPagesAndTerminate: page size 2 over 5 entries returns 3
// pages and terminates with an empty cookie (T-140 acceptance).
func TestPagedResultsPagesAndTerminate(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, pagedOptions(t), nil)
	cl := dialTestClient(t, addr)

	var cookie []byte
	total, pages := 0, 0
	for {
		entries, done, next := pagedPage(t, cl, cookie)
		if done.Result.Code != ResultSuccess {
			t.Fatalf("paged search: %v", done.Result)
		}
		if len(entries) > 2 {
			t.Fatalf("page size = %d, want <= 2", len(entries))
		}
		if len(entries) == 0 {
			t.Fatalf("page %d empty before termination", pages+1)
		}
		total += len(entries)
		pages++
		if pages > 10 {
			t.Fatal("paging did not terminate")
		}
		if len(next) == 0 {
			break
		}
		cookie = next
	}
	if pages != 3 || total != 5 {
		t.Fatalf("pages = %d, total = %d; want 3 pages, 5 entries", pages, total)
	}
}

// TestPagedResultsTamperedCookieFails: bit-flipped MAC, rebased offset,
// truncated cookie, and cross-query replay all fail (T-140 acceptance).
// The failure code is unwillingToPerform; 389's code for a bad cookie is a
// Delta candidate for the T-147 oracle.
func TestPagedResultsTamperedCookieFails(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, pagedOptions(t), nil)
	cl := dialTestClient(t, addr)

	_, done, cookie := pagedPage(t, cl, nil)
	if done.Result.Code != ResultSuccess || len(cookie) == 0 {
		t.Fatalf("first page: %v", done.Result)
	}

	searchWith := func(c []byte) *SearchResultDone {
		t.Helper()
		ctrl := Control{OID: OIDSimplePagedResults, Value: encodePagedCookie(2, c)}
		_, done, _ := searchFull(t, cl, &SearchRequest{
			BaseDN: "ou=people,dc=example,dc=test", Scope: ScopeSingleLevel,
			Filter: &FilterPresent{Attr: "objectClass"},
		}, ctrl)
		return done
	}

	// Flip one character inside the MAC region.
	forged := append([]byte(nil), cookie...)
	forged[len(forged)-1] = 'A' + (forged[len(forged)-1]+1)%26
	if done := searchWith(forged); done.Result.Code != ResultUnwillingToPerform {
		t.Fatalf("MAC-flipped cookie: %v, want unwillingToPerform", done.Result)
	}
	// Rebase: keep the MAC, change the offset digits.
	parts := strings.SplitN(string(cookie), ".", 3)
	if len(parts) != 3 {
		t.Fatalf("cookie shape: %d parts", len(parts))
	}
	if done := searchWith([]byte(parts[0] + ".0." + parts[2])); done.Result.Code != ResultUnwillingToPerform {
		t.Fatalf("offset-rebased cookie: %v, want unwillingToPerform", done.Result)
	}
	// Truncated cookie.
	if done := searchWith(cookie[:len(cookie)/2]); done.Result.Code != ResultUnwillingToPerform {
		t.Fatalf("truncated cookie: %v, want unwillingToPerform", done.Result)
	}
	// Cross-query replay: same cookie, different filter.
	ctrl := Control{OID: OIDSimplePagedResults, Value: encodePagedCookie(2, cookie)}
	_, done, _ = searchFull(t, cl, &SearchRequest{
		BaseDN: "ou=people,dc=example,dc=test", Scope: ScopeSingleLevel,
		Filter: &FilterEquality{Attr: "uid", Value: []byte("user1")},
	}, ctrl)
	if done.Result.Code != ResultUnwillingToPerform {
		t.Fatalf("cross-filter replay: %v, want unwillingToPerform", done.Result)
	}
	// Cross-base replay: same cookie, different base DN.
	_, done, _ = searchFull(t, cl, &SearchRequest{
		BaseDN: "dc=example,dc=test", Scope: ScopeWholeSubtree,
		Filter: &FilterPresent{Attr: "objectClass"},
	}, ctrl)
	if done.Result.Code != ResultUnwillingToPerform {
		t.Fatalf("cross-base replay: %v, want unwillingToPerform", done.Result)
	}

	// The honest cookie still pages correctly afterwards.
	entries, done, _ := pagedPage(t, cl, cookie)
	if done.Result.Code != ResultSuccess || len(entries) != 2 {
		t.Fatalf("second page with valid cookie: %v, %d entries", done.Result, len(entries))
	}
}

// TestPagedResultsCookiePerServerInstance: the signing key is generated per
// server instance, so a cookie issued by one server fails on another.
func TestPagedResultsCookiePerServerInstance(t *testing.T) {
	t.Parallel()
	_, addrA := serveTestServerFrom(t, pagedOptions(t), nil)
	_, addrB := serveTestServerFrom(t, pagedOptions(t), nil)
	clA := dialTestClient(t, addrA)
	clB := dialTestClient(t, addrB)

	_, done, cookie := pagedPage(t, clA, nil)
	if done.Result.Code != ResultSuccess || len(cookie) == 0 {
		t.Fatalf("first page: %v", done.Result)
	}
	ctrl := Control{OID: OIDSimplePagedResults, Value: encodePagedCookie(2, cookie)}
	_, done, _ = searchFull(t, clB, &SearchRequest{
		BaseDN: "ou=people,dc=example,dc=test", Scope: ScopeSingleLevel,
		Filter: &FilterPresent{Attr: "objectClass"},
	}, ctrl)
	if done.Result.Code != ResultUnwillingToPerform {
		t.Fatalf("cross-server cookie: %v, want unwillingToPerform", done.Result)
	}
}

// TestPagedResultsCriticalUnknownControl: a critical control the engine
// does not honor fails the operation with unavailableCriticalExtension
// (parity contract C9; T-140 acceptance).
func TestPagedResultsCriticalUnknownControl(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, pagedOptions(t), nil)
	cl := dialTestClient(t, addr)

	unknown := Control{OID: "1.2.3.4.5.6.7.8.9", Critical: true, Value: []byte{0x30, 0x00}}
	_, done, _ := searchFull(t, cl, &SearchRequest{
		BaseDN: "ou=people,dc=example,dc=test", Scope: ScopeSingleLevel,
		Filter: &FilterPresent{Attr: "objectClass"},
	}, unknown)
	if done.Result.Code != ResultUnavailableCriticalExtension {
		t.Fatalf("critical unknown control: %v, want unavailableCriticalExtension", done.Result)
	}

	// The same control non-critical is ignored (RFC 4511 section 4.1.11).
	unknown.Critical = false
	entries, done, _ := searchFull(t, cl, &SearchRequest{
		BaseDN: "ou=people,dc=example,dc=test", Scope: ScopeSingleLevel,
		Filter: &FilterPresent{Attr: "objectClass"},
	}, unknown)
	if done.Result.Code != ResultSuccess || len(entries) != 5 {
		t.Fatalf("non-critical unknown control: %v, %d entries", done.Result, len(entries))
	}
}

// TestPagedResultsOutOfRangeSignedCookie: a validly signed cookie whose
// offset exceeds the (shrunken) result set yields an empty page and an
// empty cookie, not an error (T-127 behavior kept under integrity).
func TestPagedResultsOutOfRangeSignedCookie(t *testing.T) {
	t.Parallel()
	s, err := New(testOptions())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	base, err := config.ParseDN("ou=people,dc=example,dc=test")
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}
	req := &SearchRequest{Scope: ScopeSingleLevel, Filter: &FilterPresent{Attr: "objectClass"}}
	binding, err := pagedQueryBinding(base, req)
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	page := &pageRequest{size: 2, offset: 99, binding: binding}
	matched := []*Entry{{DN: "uid=a"}, {DN: "uid=b"}, {DN: "uid=c"}}
	controls, res := s.applyPaging(matched, page, 500)
	if len(res.out) != 0 {
		t.Fatalf("out-of-range page = %d entries, want 0", len(res.out))
	}
	if len(res.nextCookie) != 0 {
		t.Fatalf("out-of-range cookie = %q, want empty", res.nextCookie)
	}
	if len(controls) != 1 || controls[0].OID != OIDSimplePagedResults {
		t.Fatalf("response controls = %+v", controls)
	}
}

// TestPagedCookieRedaction: a rejected cookie never appears in the log —
// cookie bytes may embed query state (AGENTS.md logging rules).
func TestPagedCookieRedaction(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	var logMu sync.Mutex
	logger := slog.New(slog.NewTextHandler(&lockedWriter{mu: &logMu, w: &buf}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	opts := pagedOptions(t)
	opts.Logger = logger
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)

	marker := "n0tARealC00kie-marker"
	ctrl := Control{OID: OIDSimplePagedResults, Value: encodePagedCookie(2, []byte(marker))}
	_, done, _ := searchFull(t, cl, &SearchRequest{
		BaseDN: "ou=people,dc=example,dc=test", Scope: ScopeSingleLevel,
		Filter: &FilterPresent{Attr: "objectClass"},
	}, ctrl)
	if done.Result.Code != ResultUnwillingToPerform {
		t.Fatalf("bad cookie: %v, want unwillingToPerform", done.Result)
	}
	if strings.Contains(done.Result.DiagnosticMessage, marker) {
		t.Fatalf("diagnostic echoes cookie: %q", done.Result.DiagnosticMessage)
	}
	logMu.Lock()
	out := buf.String()
	logMu.Unlock()
	if strings.Contains(out, marker) {
		t.Fatalf("log contains cookie content:\n%s", out)
	}
}
