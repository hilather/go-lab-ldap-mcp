package ldapserver

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// searchSchema registers the attributes the tests match on, with 389-style
// equality rules: caseIgnoreMatch for name-like attributes, exact octets
// otherwise.
func searchSchema() *FakeSchema {
	return NewFakeSchema(nil, []AttributeTypeDef{
		{OID: "2.5.4.3", Name: "cn", Equality: "caseIgnoreMatch"},
		{OID: "2.5.4.4", Name: "sn", Equality: "caseIgnoreMatch"},
		{OID: "2.5.4.11", Name: "ou", Equality: "caseIgnoreMatch"},
		{OID: "2.5.4.0", Name: "objectClass", Equality: "caseIgnoreMatch"},
		{OID: "0.9.2342.19200300.100.1.1", Name: "uid", Equality: "caseIgnoreMatch"},
		{OID: "2.5.4.50", Name: "uniqueMember", Equality: "distinguishedNameMatch"},
		{OID: "2.5.4.31", Name: "member", Equality: "distinguishedNameMatch"},
		{OID: "1.2.3.4", Name: "x-bin", Equality: "octetStringMatch"},
		{OID: "1.1.1.1", Name: "entryUUID", Equality: "caseIgnoreMatch", Operational: true},
	})
}

// searchOptions seeds a small tree and allows all ACI checks.
func searchOptions(t *testing.T, mutate func(*Options)) Options {
	t.Helper()
	opts := testOptions()
	opts.Codec = NewBERCodec(BERCodecOptions{})
	opts.Schema = searchSchema()
	opts.ACI = &FakeACI{Decide: func(ctx context.Context, tx ReadTx, check ACICheck) (bool, error) {
		return true, nil
	}}
	ctx := context.Background()
	err := opts.Store.Update(ctx, func(tx UpdateTx) error {
		for _, e := range []*Entry{
			NewEntry("dc=example,dc=test",
				StringAttribute("objectClass", "top", "domain"),
				StringAttribute("entryUUID", "root-uuid")),
			NewEntry("ou=people,dc=example,dc=test",
				StringAttribute("objectClass", "top", "organizationalUnit"),
				StringAttribute("ou", "people")),
			NewEntry("uid=alice,ou=people,dc=example,dc=test",
				StringAttribute("objectClass", "top", "person"),
				StringAttribute("uid", "alice"),
				StringAttribute("cn", "Alice Adams"),
				StringAttribute("sn", "Adams"),
				StringAttribute("x-bin", "blob"),
				StringAttribute("entryUUID", "uuid-alice")),
			NewEntry("uid=bob,ou=people,dc=example,dc=test",
				StringAttribute("objectClass", "top", "person"),
				StringAttribute("uid", "bob"),
				StringAttribute("cn", "Bob Brown"),
				StringAttribute("sn", "Brown"),
				StringAttribute("entryUUID", "uuid-bob")),
			NewEntry("ou=groups,dc=example,dc=test",
				StringAttribute("objectClass", "top", "organizationalUnit"),
				StringAttribute("ou", "groups")),
			NewEntry("cn=admins,ou=groups,dc=example,dc=test",
				StringAttribute("objectClass", "top", "groupOfNames"),
				StringAttribute("cn", "admins"),
				StringAttribute("member", "uid=alice,ou=people,dc=example,dc=test")),
		} {
			if err := tx.Add(ctx, e); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if mutate != nil {
		mutate(&opts)
	}
	return opts
}

// sendRaw writes one message with controls and returns its ID.
func (c *ldapTestClient) sendRaw(op Operation, controls []Control) int64 {
	c.t.Helper()
	c.nextID++
	if err := c.codec.WriteMessage(context.Background(), c.conn, &Message{ID: c.nextID, Op: op, Controls: controls}); err != nil {
		c.t.Fatalf("write: %v", err)
	}
	return c.nextID
}

// searchFull drives a search over the wire and returns the entries, the
// SearchResultDone, and the done message's controls.
func searchFull(t *testing.T, cl *ldapTestClient, req *SearchRequest, controls ...Control) ([]*SearchResultEntry, *SearchResultDone, []Control) {
	t.Helper()
	id := cl.sendRaw(req, controls)
	var entries []*SearchResultEntry
	for {
		m := cl.recv()
		if m.ID != id {
			t.Fatalf("response id = %d, want %d", m.ID, id)
		}
		switch op := m.Op.(type) {
		case *SearchResultEntry:
			entries = append(entries, op)
		case *SearchResultDone:
			return entries, op, m.Controls
		default:
			t.Fatalf("unexpected op %T", m.Op)
		}
	}
}

func search(t *testing.T, cl *ldapTestClient, req *SearchRequest) ([]*SearchResultEntry, *SearchResultDone) {
	t.Helper()
	entries, done, _ := searchFull(t, cl, req)
	return entries, done
}

func TestSearchScopes(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, searchOptions(t, nil), nil)
	cl := dialTestClient(t, addr)

	// Base.
	entries, done := search(t, cl, &SearchRequest{
		BaseDN: "uid=alice,ou=people,dc=example,dc=test",
		Scope:  ScopeBaseObject, Filter: &FilterPresent{Attr: "objectClass"},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 1 || entries[0].DN != "uid=alice,ou=people,dc=example,dc=test" {
		t.Fatalf("base search: %v, %v", done.Result, entries)
	}

	// Base on a missing DN: noSuchObject (T-127 acceptance).
	_, done = search(t, cl, &SearchRequest{
		BaseDN: "uid=ghost,ou=people,dc=example,dc=test",
		Scope:  ScopeBaseObject, Filter: &FilterPresent{Attr: "objectClass"},
	})
	if done.Result.Code != ResultNoSuchObject {
		t.Fatalf("missing base: %v, want noSuchObject", done.Result)
	}

	// Invalid base DN syntax.
	_, done = search(t, cl, &SearchRequest{
		BaseDN: "not-a-dn", Scope: ScopeBaseObject,
		Filter: &FilterPresent{Attr: "objectClass"},
	})
	if done.Result.Code != ResultInvalidDNSyntax {
		t.Fatalf("invalid base: %v, want invalidDNSyntax", done.Result)
	}

	// One level: exactly the two users.
	entries, done = search(t, cl, &SearchRequest{
		BaseDN: "ou=people,dc=example,dc=test",
		Scope:  ScopeSingleLevel, Filter: &FilterPresent{Attr: "objectClass"},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 2 {
		t.Fatalf("one-level: %v, %d entries", done.Result, len(entries))
	}

	// Subtree from the suffix: everything.
	entries, done = search(t, cl, &SearchRequest{
		BaseDN: "dc=example,dc=test",
		Scope:  ScopeWholeSubtree, Filter: &FilterPresent{Attr: "objectClass"},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 6 {
		t.Fatalf("subtree: %v, %d entries", done.Result, len(entries))
	}
}

func TestSearchFilters(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, searchOptions(t, nil), nil)
	cl := dialTestClient(t, addr)
	base := "dc=example,dc=test"

	count := func(f Filter) int {
		t.Helper()
		entries, done := search(t, cl, &SearchRequest{BaseDN: base, Scope: ScopeWholeSubtree, Filter: f})
		if done.Result.Code != ResultSuccess {
			t.Fatalf("search: %v", done.Result)
		}
		return len(entries)
	}

	// Equality folds case per the schema's caseIgnoreMatch (stub matching
	// rules until T-131).
	if n := count(&FilterEquality{Attr: "uid", Value: []byte("ALICE")}); n != 1 {
		t.Fatalf("caseIgnore equality = %d", n)
	}
	// Exact-octet attribute: case differs, no match.
	if n := count(&FilterEquality{Attr: "x-bin", Value: []byte("BLOB")}); n != 0 {
		t.Fatalf("octet equality = %d", n)
	}
	if n := count(&FilterEquality{Attr: "x-bin", Value: []byte("blob")}); n != 1 {
		t.Fatalf("octet equality match = %d", n)
	}
	if n := count(&FilterAnd{Children: []Filter{
		&FilterEquality{Attr: "objectClass", Value: []byte("person")},
		&FilterEquality{Attr: "sn", Value: []byte("adams")},
	}}); n != 1 {
		t.Fatalf("and = %d", n)
	}
	if n := count(&FilterOr{Children: []Filter{
		&FilterEquality{Attr: "uid", Value: []byte("alice")},
		&FilterEquality{Attr: "uid", Value: []byte("bob")},
	}}); n != 2 {
		t.Fatalf("or = %d", n)
	}
	if n := count(&FilterNot{Child: &FilterPresent{Attr: "uid"}}); n != 4 {
		t.Fatalf("not = %d", n)
	}
	if n := count(&FilterSubstrings{Attr: "cn", Initial: []byte("ali")}); n != 1 {
		t.Fatalf("substring initial = %d", n)
	}
	if n := count(&FilterSubstrings{Attr: "cn", Any: [][]byte{[]byte("brown")}}); n != 1 {
		t.Fatalf("substring any = %d", n)
	}
	if n := count(&FilterSubstrings{Attr: "cn", Final: []byte("AMS")}); n != 1 {
		t.Fatalf("substring final (folded) = %d", n)
	}
	if n := count(&FilterGreaterOrEqual{Attr: "uid", Value: []byte("b")}); n != 1 {
		t.Fatalf("ge = %d", n)
	}
	if n := count(&FilterLessOrEqual{Attr: "uid", Value: []byte("alice")}); n != 1 {
		t.Fatalf("le = %d", n)
	}
	// Approx folds to equality (389-observed; see matchFilter comment).
	if n := count(&FilterApproxMatch{Attr: "cn", Value: []byte("alice adams")}); n != 1 {
		t.Fatalf("approx = %d", n)
	}
	// Present matches only entries carrying the attribute.
	if n := count(&FilterPresent{Attr: "member"}); n != 1 {
		t.Fatalf("present = %d", n)
	}
}

func TestSearchAttributeSelection(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, searchOptions(t, nil), nil)
	cl := dialTestClient(t, addr)
	base := &SearchRequest{
		BaseDN: "uid=alice,ou=people,dc=example,dc=test",
		Scope:  ScopeBaseObject, Filter: &FilterPresent{Attr: "objectClass"},
	}

	has := func(e *SearchResultEntry, name string) bool {
		for _, a := range e.Attributes {
			if strings.EqualFold(a.Name, name) {
				return true
			}
		}
		return false
	}

	// Empty: all user attributes, no operational ones.
	entries, _ := search(t, cl, base)
	if !has(entries[0], "uid") || !has(entries[0], "cn") || has(entries[0], "entryUUID") {
		t.Fatalf("empty selection = %+v", entries[0].Attributes)
	}
	// "*" user attrs.
	req := *base
	req.Attributes = []string{"*"}
	entries, _ = search(t, cl, &req)
	if !has(entries[0], "uid") || has(entries[0], "entryUUID") {
		t.Fatalf("\"*\" selection = %+v", entries[0].Attributes)
	}
	// "+" operational only.
	req.Attributes = []string{"+"}
	entries, _ = search(t, cl, &req)
	if !has(entries[0], "entryUUID") || has(entries[0], "uid") {
		t.Fatalf("\"+\" selection = %+v", entries[0].Attributes)
	}
	// "*", "+" both.
	req.Attributes = []string{"*", "+"}
	entries, _ = search(t, cl, &req)
	if !has(entries[0], "uid") || !has(entries[0], "entryUUID") {
		t.Fatalf("\"* +\" selection = %+v", entries[0].Attributes)
	}
	// Named subset, case-insensitive.
	req.Attributes = []string{"SN"}
	entries, _ = search(t, cl, &req)
	if len(entries[0].Attributes) != 1 || !has(entries[0], "sn") {
		t.Fatalf("named selection = %+v", entries[0].Attributes)
	}
	// "1.1": no attributes.
	req.Attributes = []string{"1.1"}
	entries, _ = search(t, cl, &req)
	if len(entries[0].Attributes) != 0 {
		t.Fatalf("1.1 selection = %+v", entries[0].Attributes)
	}
	// typesOnly: names without values.
	req.Attributes = nil
	req.TypesOnly = true
	entries, _ = search(t, cl, &req)
	for _, a := range entries[0].Attributes {
		if len(a.Values) != 0 {
			t.Fatalf("typesOnly carried values: %+v", a)
		}
	}
}

func TestSearchSizeLimitEnforcedServerSide(t *testing.T) {
	t.Parallel()
	// Client requests 2 over 6 entries.
	_, addr := serveTestServerFrom(t, searchOptions(t, nil), nil)
	cl := dialTestClient(t, addr)
	entries, done := search(t, cl, &SearchRequest{
		BaseDN: "dc=example,dc=test", Scope: ScopeWholeSubtree,
		SizeLimit: 2, Filter: &FilterPresent{Attr: "objectClass"},
	})
	if done.Result.Code != ResultSizeLimitExceeded || len(entries) != 2 {
		t.Fatalf("client size limit: %v, %d entries", done.Result, len(entries))
	}
	// Client asks unlimited; server ceiling 3 applies (C6).
	_, addr2 := serveTestServerFrom(t, searchOptions(t, func(o *Options) {
		o.Limits.SearchSizeLimit = 3
	}), nil)
	cl2 := dialTestClient(t, addr2)
	entries, done = search(t, cl2, &SearchRequest{
		BaseDN: "dc=example,dc=test", Scope: ScopeWholeSubtree,
		Filter: &FilterPresent{Attr: "objectClass"},
	})
	if done.Result.Code != ResultSizeLimitExceeded || len(entries) != 3 {
		t.Fatalf("server size limit: %v, %d entries", done.Result, len(entries))
	}
}

func TestSearchTimeLimitEnforced(t *testing.T) {
	t.Parallel()
	// A nanosecond ceiling expires before the first candidate is checked.
	_, addr := serveTestServerFrom(t, searchOptions(t, func(o *Options) {
		o.Limits.SearchTimeLimit = time.Nanosecond
	}), nil)
	cl := dialTestClient(t, addr)
	_, done := search(t, cl, &SearchRequest{
		BaseDN: "dc=example,dc=test", Scope: ScopeWholeSubtree,
		Filter: &FilterPresent{Attr: "objectClass"},
	})
	if done.Result.Code != ResultTimeLimitExceeded {
		t.Fatalf("time limit: %v, want timeLimitExceeded", done.Result)
	}
}

func TestSearchACIDeniedEntriesFiltered(t *testing.T) {
	t.Parallel()
	// Deny-by-default ACI (FakeACI zero value): the search succeeds with an
	// empty result instead of failing or leaking existence (C8).
	opts := searchOptions(t, nil)
	opts.ACI = &FakeACI{}
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	entries, done := search(t, cl, &SearchRequest{
		BaseDN: "dc=example,dc=test", Scope: ScopeWholeSubtree,
		Filter: &FilterPresent{Attr: "objectClass"},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 0 {
		t.Fatalf("denied search: %v, %d entries", done.Result, len(entries))
	}
}

func TestSearchACIDeniedAttributeDropped(t *testing.T) {
	t.Parallel()
	opts := searchOptions(t, nil)
	opts.ACI = &FakeACI{Decide: func(ctx context.Context, tx ReadTx, check ACICheck) (bool, error) {
		if check.Perm == PermRead && strings.EqualFold(check.Attribute, "x-bin") {
			return false, nil
		}
		return true, nil
	}}
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	entries, done := search(t, cl, &SearchRequest{
		BaseDN: "uid=alice,ou=people,dc=example,dc=test", Scope: ScopeBaseObject,
		Filter: &FilterPresent{Attr: "objectClass"},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 1 {
		t.Fatalf("search: %v", done.Result)
	}
	for _, a := range entries[0].Attributes {
		if strings.EqualFold(a.Name, "x-bin") {
			t.Fatalf("read-denied attribute returned: %+v", entries[0].Attributes)
		}
	}
}

// decodePagedCookie pulls the cookie out of a paged-results response
// control for the next request.
func decodePagedCookie(t *testing.T, controls []Control) []byte {
	t.Helper()
	for _, ctrl := range controls {
		if ctrl.OID != OIDSimplePagedResults {
			continue
		}
		pr, res, err := parsePagedControl([]Control{ctrl})
		if err != nil {
			t.Fatalf("response control parse: %v (%v)", err, res)
		}
		if pr.offset == 0 {
			return nil
		}
		return []byte(strconv.Itoa(pr.offset))
	}
	return nil
}

func TestSearchPagedResults(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, searchOptions(t, nil), nil)
	cl := dialTestClient(t, addr)

	var cookie []byte
	total, pages := 0, 0
	for {
		ctrl := Control{OID: OIDSimplePagedResults, Value: encodePagedCookie(2, cookie)}
		entries, done, respControls := searchFull(t, cl, &SearchRequest{
			BaseDN: "dc=example,dc=test", Scope: ScopeWholeSubtree,
			Filter: &FilterPresent{Attr: "objectClass"},
		}, ctrl)
		if done.Result.Code != ResultSuccess {
			t.Fatalf("paged search: %v", done.Result)
		}
		if len(entries) > 2 {
			t.Fatalf("page size = %d, want <= 2", len(entries))
		}
		total += len(entries)
		pages++
		if pages > 10 {
			t.Fatal("paging did not terminate")
		}
		cookie = decodePagedCookie(t, respControls)
		if len(cookie) == 0 {
			break
		}
	}
	// 6 entries, page size 2: 3 full pages then a final empty-page request
	// with the exhausted cookie returns the terminating empty cookie.
	if total != 6 {
		t.Fatalf("paged total = %d, want 6", total)
	}

	// Index out of range: an offset beyond the result set returns an empty
	// page and an empty cookie, not an error (T-127 acceptance).
	ctrl := Control{OID: OIDSimplePagedResults, Value: encodePagedCookie(2, []byte("999"))}
	entries, done, respControls := searchFull(t, cl, &SearchRequest{
		BaseDN: "dc=example,dc=test", Scope: ScopeWholeSubtree,
		Filter: &FilterPresent{Attr: "objectClass"},
	}, ctrl)
	if done.Result.Code != ResultSuccess || len(entries) != 0 {
		t.Fatalf("out-of-range page: %v, %d entries", done.Result, len(entries))
	}
	if c := decodePagedCookie(t, respControls); len(c) != 0 {
		t.Fatalf("out-of-range cookie = %q, want empty", c)
	}

	// A malformed cookie fails cleanly (cookie integrity lands in T-140).
	ctrl = Control{OID: OIDSimplePagedResults, Value: encodePagedCookie(2, []byte("garbage"))}
	_, done, _ = searchFull(t, cl, &SearchRequest{
		BaseDN: "dc=example,dc=test", Scope: ScopeWholeSubtree,
		Filter: &FilterPresent{Attr: "objectClass"},
	}, ctrl)
	if done.Result.Code != ResultUnwillingToPerform {
		t.Fatalf("bad cookie: %v, want unwillingToPerform", done.Result)
	}
}

// TestSearchAbandonedStopsWorker abandons an in-flight search whose store
// Subtree is blocked, proving Abandon cancels the worker (RFC 4511 4.11).
func TestSearchAbandonedStopsWorker(t *testing.T) {
	t.Parallel()
	gate := make(chan struct{})
	opts := searchOptions(t, nil)
	opts.Store = &blockingStore{Store: opts.Store, gate: gate}
	s, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	id := cl.sendRaw(&SearchRequest{
		BaseDN: "dc=example,dc=test", Scope: ScopeWholeSubtree,
		Filter: &FilterPresent{Attr: "objectClass"},
	}, nil)
	// Give the worker a moment to reach the blocked Subtree, then abandon.
	time.Sleep(100 * time.Millisecond)
	cl.send(&AbandonRequest{MessageID: id})
	// The worker's context is canceled: the blocked store read releases
	// through ctx, the worker finishes without sending a response.
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.connsMu.Lock()
		var sc *conn
		for c := range s.conns {
			sc = c
		}
		s.connsMu.Unlock()
		if sc != nil {
			sc.mu.Lock()
			n := len(sc.inflight)
			sc.mu.Unlock()
			if n == 0 {
				close(gate)
				return
			}
		}
		if time.Now().After(deadline) {
			close(gate)
			t.Fatal("abandoned search worker still in flight")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// blockingStore wraps a Store and blocks Subtree until the gate closes or
// the caller's context is canceled.
type blockingStore struct {
	Store
	gate chan struct{}
}

func (s *blockingStore) View(ctx context.Context, fn func(tx ReadTx) error) error {
	return s.Store.View(ctx, func(tx ReadTx) error {
		return fn(&blockingTx{ReadTx: tx, gate: s.gate})
	})
}

type blockingTx struct {
	ReadTx
	gate chan struct{}
}

func (t *blockingTx) Subtree(ctx context.Context, dn config.DN) ([]*Entry, error) {
	select {
	case <-t.gate:
		return t.ReadTx.Subtree(ctx, dn)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
