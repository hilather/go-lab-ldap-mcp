package ldapserver

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

// FuzzDispatchPDU is the T-149 dispatch-level fuzz target: bytes are
// decoded by the real BER codec and every successfully decoded request is
// handed to Server.dispatchOp on a live net.Pipe, so the fuzzer drives the
// full pre-auth handler surface (search, add, modify, delete, modifyDN,
// compare, extended, and the defensive default case) rather than just the
// decoder.
//
// Invariants:
//
//   - no panic, no hang: every dispatched op terminates within a deadline
//   - every op produces exactly one terminating response and every PDU the
//     server emits is itself decodable
//   - the shared seeded store stays coherent across arbitrary writes (the
//     fuzzer mutates it; a corrupting write would fail a later iteration's
//     response decode)
//
// Smoke: go test -fuzz=FuzzDispatchPDU -fuzztime=30s ./internal/ldapserver/
func FuzzDispatchPDU(f *testing.F) {
	srv, cleanup := fuzzDispatchServer(f)
	defer cleanup()
	for _, seed := range fuzzDispatchSeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		codec := NewBERCodec(BERCodecOptions{})
		msg, err := codec.ReadMessage(context.Background(), bytes.NewReader(data))
		if err != nil {
			return // undecodable: FuzzDecode owns that contract
		}
		defer ZeroSecrets(msg)

		serverEnd, clientEnd := net.Pipe()
		defer func() { _ = serverEnd.Close(); _ = clientEnd.Close() }()
		c := srv.newConn(context.Background(), serverEnd, false)

		done := make(chan struct{})
		go func() {
			defer close(done)
			srv.dispatchOp(context.Background(), c, msg)
		}()

		// Read until the terminating response for this op. net.Pipe is
		// synchronous, so the handler blocks on write until we read.
		responses := 0
		for {
			_ = clientEnd.SetReadDeadline(time.Now().Add(5 * time.Second))
			resp, err := codec.ReadMessage(context.Background(), clientEnd)
			if err != nil {
				t.Fatalf("server emitted undecodable PDU for op %s: %v", opName(msg.Op), err)
			}
			responses++
			if responses > 64 {
				t.Fatalf("op %s produced a response flood", opName(msg.Op))
			}
			switch resp.Op.(type) {
			case *SearchResultEntry:
				ZeroSecrets(resp)
				continue // intermediate; the done message terminates
			case *SearchResultDone, *BindResponse, *AddResponse, *ModifyResponse,
				*DeleteResponse, *ModifyDNResponse, *CompareResponse, *ExtendedResponse:
				ZeroSecrets(resp)
				goto terminated
			default:
				t.Fatalf("op %s produced unexpected response %T", opName(msg.Op), resp.Op)
			}
		}
	terminated:
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("dispatch of op %s did not return after its response", opName(msg.Op))
		}
	})
}

// fuzzDispatchServer builds one production-shaped in-process server for
// the whole fuzz run: standard schema, DM identity, DM-bypass ACI, and a
// seeded suffix so handlers walk real store paths. Not bound as DM: the
// anonymous subject exercises the deny paths.
func fuzzDispatchServer(f *testing.F) (*Server, func()) {
	f.Helper()
	schema, err := StandardSchema()
	if err != nil {
		f.Fatalf("StandardSchema: %v", err)
	}
	opts := testOptions()
	opts.Codec = NewBERCodec(BERCodecOptions{})
	opts.Schema = schema
	opts.AllowCleartextBind = true
	// Keep the fuzzer on the handler surface; anonymous-off refusal is
	// unit-tested, not the fuzz contract.
	opts.AllowAnonymousBind = true
	opts.DirectoryManager = dmIdentity(diffDMFixturePassword)
	opts.ACI = &FakeACI{Decide: func(ctx context.Context, tx ReadTx, check ACICheck) (bool, error) {
		return check.Subject.BypassACI, nil
	}}
	ctx := context.Background()
	err = opts.Store.Update(ctx, func(tx UpdateTx) error {
		for _, e := range []*Entry{
			NewEntry("dc=example,dc=test",
				StringAttribute("objectClass", "top", "domain"),
				StringAttribute("dc", "example")),
			NewEntry("ou=people,dc=example,dc=test",
				StringAttribute("objectClass", "top", "organizationalUnit"),
				StringAttribute("ou", "people")),
			NewEntry("uid=alice,ou=people,dc=example,dc=test",
				StringAttribute("objectClass", "top", "person", "organizationalPerson", "inetOrgPerson"),
				StringAttribute("uid", "alice"),
				StringAttribute("cn", "Alice Adams"),
				StringAttribute("sn", "Adams"),
				StringAttribute("userPassword", "alice-fuzz-fixture")),
		} {
			if err := tx.Add(ctx, e); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		f.Fatalf("seed: %v", err)
	}
	srv, err := New(opts)
	if err != nil {
		f.Fatalf("New: %v", err)
	}
	return srv, func() { _ = srv.Close() }
}

// fuzzDispatchSeeds returns one encoded wire message per op family. The
// committed BER goldens under testdata/golden are replayed by FuzzDecode;
// these seeds aim the mutator at dispatch. Values are fixtures, not
// credentials.
func fuzzDispatchSeeds(f *testing.F) [][]byte {
	f.Helper()
	codec := NewBERCodec(BERCodecOptions{})
	msgs := []*Message{
		{ID: 1, Op: &SearchRequest{
			BaseDN: "dc=example,dc=test", Scope: ScopeWholeSubtree,
			Filter: &FilterPresent{Attr: "objectClass"},
		}},
		{ID: 2, Op: &SearchRequest{
			BaseDN: "ou=people,dc=example,dc=test", Scope: ScopeSingleLevel,
			Filter: &FilterAnd{Children: []Filter{
				&FilterEquality{Attr: "uid", Value: []byte("alice")},
				&FilterNot{Child: &FilterPresent{Attr: "sn"}},
			}},
			SizeLimit: 1,
		}, Controls: []Control{{OID: OIDSimplePagedResults, Value: encodePagedCookie(1, nil)}}},
		{ID: 3, Op: &AddRequest{
			DN: "uid=fuzz,ou=people,dc=example,dc=test",
			Attributes: []Attribute{
				{Name: "objectClass", Values: [][]byte{[]byte("top"), []byte("person")}},
				{Name: "uid", Values: [][]byte{[]byte("fuzz")}},
				{Name: "cn", Values: [][]byte{[]byte("Fuzz")}},
				{Name: "sn", Values: [][]byte{[]byte("Fuzz")}},
			},
		}},
		{ID: 4, Op: &ModifyRequest{
			DN:      "uid=alice,ou=people,dc=example,dc=test",
			Changes: []ModifyChange{{Op: ModifyReplace, Attr: StringAttribute("description", "x")}},
		}},
		{ID: 5, Op: &DeleteRequest{DN: "uid=fuzz,ou=people,dc=example,dc=test"}},
		{ID: 6, Op: &ModifyDNRequest{
			DN: "uid=alice,ou=people,dc=example,dc=test", NewRDN: "uid=alice2", DeleteOldRDN: true,
		}},
		{ID: 7, Op: &CompareRequest{
			DN: "uid=alice,ou=people,dc=example,dc=test", Attr: "uid", Value: []byte("alice"),
		}},
		{ID: 8, Op: &ExtendedRequest{Name: OIDWhoAmI}},
		{ID: 9, Op: &ExtendedRequest{Name: "1.2.3.4.5.6.7", Value: []byte{0x01, 0x02}}},
		{ID: 10, Op: &BindRequest{Version: 3, Name: "cn=Directory Manager", Password: []byte("fuzz-seed-not-a-credential")}},
		{ID: 11, Op: &UnbindRequest{}},
		{ID: 12, Op: &AbandonRequest{MessageID: 1}},
	}
	out := make([][]byte, 0, len(msgs))
	for _, m := range msgs {
		var buf bytes.Buffer
		if err := codec.WriteMessage(context.Background(), &buf, m); err != nil {
			f.Fatalf("seed encode %T: %v", m.Op, err)
		}
		out = append(out, buf.Bytes())
	}
	return out
}
