package ldapserver

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testOptions returns a valid Options built entirely on fakes; table cases
// mutate it to prove constructor validation.
func testOptions() Options {
	return Options{
		Suffix:      "dc=example,dc=test",
		LDAPAddress: "127.0.0.1:3389",
		Codec:       NewFakeCodec(),
		Store:       NewFakeStore(),
		Schema:      NewFakeSchema(nil, nil),
		ACI:         &FakeACI{},
		Logger:      testLogger(),
	}
}

func TestNewServer(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		mutate  func(*Options)
		wantErr bool
	}{
		{name: "valid with fakes", mutate: func(*Options) {}},
		{name: "valid with all listeners and dm", mutate: func(o *Options) {
			o.LDAPSAddress = "127.0.0.1:3636"
			o.AllowStartTLS = true
			o.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			o.DirectoryManager = Identity{
				DN:             "cn=Directory Manager",
				VerifyPassword: func([]byte) bool { return false },
			}
			o.Plugins = []Plugin{&FakePlugin{PluginName: "memberof"}}
		}},
		{name: "missing codec", mutate: func(o *Options) { o.Codec = nil }, wantErr: true},
		{name: "missing store", mutate: func(o *Options) { o.Store = nil }, wantErr: true},
		{name: "missing schema", mutate: func(o *Options) { o.Schema = nil }, wantErr: true},
		{name: "missing aci engine", mutate: func(o *Options) { o.ACI = nil }, wantErr: true},
		{name: "missing logger", mutate: func(o *Options) { o.Logger = nil }, wantErr: true},
		{name: "empty suffix", mutate: func(o *Options) { o.Suffix = "" }, wantErr: true},
		{name: "invalid suffix", mutate: func(o *Options) { o.Suffix = "not-a-dn" }, wantErr: true},
		{name: "invalid dm dn", mutate: func(o *Options) {
			o.DirectoryManager = Identity{DN: "not-a-dn", VerifyPassword: func([]byte) bool { return true }}
		}, wantErr: true},
		{name: "dm without verifier", mutate: func(o *Options) {
			o.DirectoryManager = Identity{DN: "cn=Directory Manager"}
		}, wantErr: true},
		{name: "ldaps without tls config", mutate: func(o *Options) {
			o.LDAPSAddress = "127.0.0.1:3636"
		}, wantErr: true},
		{name: "starttls without tls config", mutate: func(o *Options) {
			o.AllowStartTLS = true
		}, wantErr: true},
		{name: "invalid listen address", mutate: func(o *Options) {
			o.LDAPAddress = "no-port"
		}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := testOptions()
			tc.mutate(&opts)
			s, err := New(opts)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if s == nil {
				t.Fatal("New returned nil server")
			}
		})
	}
}

func TestNewServerDefaults(t *testing.T) {
	t.Parallel()
	s, err := New(testOptions())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := s.Suffix().String(); got != "dc=example,dc=test" {
		t.Fatalf("suffix = %q", got)
	}
	if got := s.Limits(); got != DefaultLimits() {
		t.Fatalf("limits = %+v, want defaults %+v", got, DefaultLimits())
	}
	partial := testOptions()
	partial.Limits = Limits{MaxPDUBytes: 4096, SearchTimeLimit: time.Second}
	s2, err := New(partial)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := s2.Limits().MaxPDUBytes; got != 4096 {
		t.Fatalf("MaxPDUBytes = %d", got)
	}
	if got := s2.Limits().SearchSizeLimit; got != DefaultLimits().SearchSizeLimit {
		t.Fatalf("SearchSizeLimit = %d, want default", got)
	}
}

func TestNewServerLoopbackDefault(t *testing.T) {
	t.Parallel()
	opts := testOptions()
	opts.LDAPAddress = ":3389"
	s, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := s.opts.LDAPAddress; got != "127.0.0.1:3389" {
		t.Fatalf("LDAPAddress = %q, want loopback-pinned", got)
	}
}

func TestServerServeRequiresListener(t *testing.T) {
	t.Parallel()
	opts := testOptions()
	opts.LDAPAddress = ""
	s, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Serve(context.Background()); err == nil {
		t.Fatal("Serve without listeners should fail with a configuration error")
	}
}

func TestServerCloseClosesStore(t *testing.T) {
	t.Parallel()
	s, err := New(testOptions())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err = s.opts.Store.View(context.Background(), func(tx ReadTx) error { return nil })
	if !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("View after Close = %v, want ErrStoreClosed", err)
	}
}
