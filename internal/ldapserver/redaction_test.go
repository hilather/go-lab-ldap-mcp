package ldapserver

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// TestServeRedactionSecretSurfaces is the T-150 native-engine redaction
// gate. TestServeRedaction (serve_test.go) covers the bind password on the
// error path; this test sweeps the wider secret surface at Debug level:
//
//   - a failed Directory Manager bind password
//   - a failed user bind password
//   - userPassword values on Add and Modify requests
//   - the stored userPassword value read back by a DM search
//
// None of these values may appear in the captured log, and the generic
// header/canary scanner must find nothing either.
func TestServeRedactionSecretSurfaces(t *testing.T) {
	t.Parallel()

	// Fixture values. None are real credentials.
	const (
		dmPassword      = diffDMFixturePassword
		dmWrongPassword = "dm-wrong-fixture-7f3a9b1c"
		alicePassword   = "alice-fixture-2c4d6e8f"
		addedPassword   = "added-fixture-0a1b2c3d"
		modPassword     = "modified-fixture-5e6f7a8b"
	)
	secrets := []string{dmPassword, dmWrongPassword, alicePassword, addedPassword, modPassword}

	var buf bytes.Buffer
	var mu sync.Mutex
	logger := slog.New(slog.NewTextHandler(&lockedWriter{mu: &mu, w: &buf}, &slog.HandlerOptions{Level: slog.LevelDebug}))

	opts := testOptions()
	opts.DirectoryManager = dmIdentity(dmPassword)
	opts.AllowCleartextBind = true
	opts.ACI = &FakeACI{Decide: func(ctx context.Context, tx ReadTx, check ACICheck) (bool, error) {
		return check.Subject.BypassACI, nil
	}}
	ctx := context.Background()
	err := opts.Store.Update(ctx, func(tx UpdateTx) error {
		for _, e := range []*Entry{
			NewEntry("dc=example,dc=test",
				StringAttribute("objectClass", "top", "domain"),
				StringAttribute("dc", "example")),
			NewEntry("ou=people,dc=example,dc=test",
				StringAttribute("objectClass", "top", "organizationalUnit"),
				StringAttribute("ou", "people")),
			NewEntry("uid=alice,ou=people,dc=example,dc=test",
				StringAttribute("objectClass", "top", "person"),
				StringAttribute("uid", "alice"),
				StringAttribute("cn", "Alice Adams"),
				StringAttribute("sn", "Adams"),
				StringAttribute("userPassword", alicePassword)),
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
	_, addr := serveTestServerFrom(t, opts, func(o *Options) { o.Logger = logger })

	// Failed DM bind (wrong password) and failed user bind.
	if res := bindResult(t, dialTestClient(t, addr), "cn=Directory Manager", dmWrongPassword); res.Code != ResultInvalidCredentials {
		t.Fatalf("wrong-dm bind = %v", res)
	}
	if res := bindResult(t, dialTestClient(t, addr), "uid=alice,ou=people,dc=example,dc=test", "alice-wrong-fixture-9z8y7x"); res.Code != ResultInvalidCredentials {
		t.Fatalf("wrong-user bind = %v", res)
	}
	secrets = append(secrets, "alice-wrong-fixture-9z8y7x")

	// Authenticated DM: Add carrying userPassword, Modify replacing it,
	// and a subtree search that reads userPassword back.
	cl := dialTestClient(t, addr)
	if res := bindResult(t, cl, "cn=Directory Manager", dmPassword); res.Code != ResultSuccess {
		t.Fatalf("dm bind: %v", res)
	}
	id := cl.send(&AddRequest{
		DN: "uid=redact,ou=people,dc=example,dc=test",
		Attributes: []Attribute{
			{Name: "objectClass", Values: [][]byte{[]byte("top"), []byte("person")}},
			{Name: "uid", Values: [][]byte{[]byte("redact")}},
			{Name: "cn", Values: [][]byte{[]byte("Redact Me")}},
			{Name: "sn", Values: [][]byte{[]byte("Redact")}},
			{Name: "userPassword", Values: [][]byte{[]byte(addedPassword)}},
		},
	})
	if m := cl.recv(); m.Op.(*AddResponse).Result.Code != ResultSuccess {
		t.Fatalf("add: %v (id %d)", m.Op.(*AddResponse).Result, id)
	}
	cl.send(&ModifyRequest{
		DN:      "uid=redact,ou=people,dc=example,dc=test",
		Changes: []ModifyChange{{Op: ModifyReplace, Attr: StringAttribute("userPassword", modPassword)}},
	})
	if m := cl.recv(); m.Op.(*ModifyResponse).Result.Code != ResultSuccess {
		t.Fatalf("modify: %v", m.Op.(*ModifyResponse).Result)
	}
	entries, done, _ := searchFull(t, cl, &SearchRequest{
		BaseDN: "dc=example,dc=test", Scope: ScopeWholeSubtree,
		Filter:     &FilterPresent{Attr: "userPassword"},
		Attributes: []string{"userPassword"},
	})
	if done.Result.Code != ResultSuccess || len(entries) == 0 {
		t.Fatalf("search: %v (%d entries)", done.Result, len(entries))
	}
	cl.send(&UnbindRequest{})

	mu.Lock()
	out := buf.String()
	mu.Unlock()
	for _, secret := range secrets {
		if strings.Contains(out, secret) {
			t.Fatalf("log contains a secret value (rule suppressed here to avoid echoing it):\n%s", out)
		}
	}
	findings, err := observability.ScanReader(strings.NewReader(out), secrets...)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("scanner found leaks: %s", observability.ReportFindings(findings))
	}
}
