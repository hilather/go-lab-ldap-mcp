package mcpserver

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func TestStdioActorAndScopesMatchHTTP(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	svc := mutationServices(newFakeUsers(), newFakeGroups(), &fakeBind{identity: "alice", password: mcpUserPass})
	s := mutationServer(t, svc, slog.New(slog.NewTextHandler(&logs, nil)))
	s.SetActor(auth.Principal{
		Kind:   auth.KindToken,
		ID:     "admin",
		Scopes: directory.ScopeSet{auth.ScopeDirectoryRead, auth.ScopeDirectoryWrite, auth.ScopeDirectoryPassword},
	})

	srvT, cliT := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx, srvT) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "labldap-stdio-test", Version: "v0.0.1"}, nil)
	sess, err := client.Connect(ctx, cliT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      ToolCreateUser,
		Arguments: CreateUserInput{ID: "stdio", Password: mcpUserPass},
	})
	if err != nil || res.IsError {
		t.Fatalf("stdio create: %+v %v", res, err)
	}
	if containsSecret(logs.String(), mcpUserPass) {
		t.Fatalf("password in stdio logs: %s", logs.String())
	}
	if strings.Contains(logs.String(), `"jsonrpc"`) || strings.Contains(logs.String(), "tools/call") {
		t.Fatalf("protocol leaked into logs: %s", logs.String())
	}

	reader := mutationServer(t, svc, slog.New(slog.NewTextHandler(io.Discard, nil)))
	reader.SetActor(auth.Principal{Kind: auth.KindToken, ID: "reader", Scopes: directory.ScopeSet{auth.ScopeDirectoryRead}})
	rSrv, rCli := mcp.NewInMemoryTransports()
	go func() { _ = reader.Run(ctx, rSrv) }()
	rsess, err := client.Connect(ctx, rCli, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rsess.Close() })
	denied, err := rsess.CallTool(ctx, &mcp.CallToolParams{
		Name:      ToolCreateUser,
		Arguments: CreateUserInput{ID: "nope", Password: mcpUserPass},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !denied.IsError {
		t.Fatal("stdio reader inherited writer scopes")
	}

	cancel()
	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("stdio run did not stop")
	}
}

type pipeWrite struct {
	io.Writer
	c io.Closer
}

func (w pipeWrite) Close() error { return w.c.Close() }

func TestStdioIOTransportProtocolStaysOnStdout(t *testing.T) {
	t.Parallel()
	var logs, proto bytes.Buffer
	svc := mutationServices(newFakeUsers(), newFakeGroups(), &fakeBind{})
	s := mutationServer(t, svc, slog.New(slog.NewTextHandler(&logs, nil)))
	s.SetActor(auth.Principal{
		Kind:   auth.KindToken,
		ID:     "admin",
		Scopes: directory.ScopeSet{auth.ScopeDirectoryRead, auth.ScopeDirectoryWrite},
	})

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Run(ctx, &mcp.IOTransport{
			Reader: inR,
			Writer: pipeWrite{Writer: io.MultiWriter(&proto, outW), c: outW},
		})
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "labldap-stdio-io", Version: "v0.0.1"}, nil)
	sess, err := client.Connect(ctx, &mcp.IOTransport{Reader: outR, Writer: inW}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      ToolCreateUser,
		Arguments: CreateUserInput{ID: "pipe", Password: mcpUserPass},
	})
	if err != nil || res.IsError {
		t.Fatalf("create: %+v %v", res, err)
	}

	wire := proto.String()
	if !strings.Contains(wire, `"jsonrpc"`) && !strings.Contains(wire, "jsonrpc") {
		t.Fatalf("protocol stream missing JSON-RPC: %q", wire)
	}
	if strings.Contains(wire, "mcp tool") || strings.Contains(logs.String(), `"jsonrpc"`) {
		t.Fatalf("log/protocol mixed: logs=%q proto=%q", logs.String(), wire)
	}
	if containsSecret(wire+logs.String(), mcpUserPass) {
		t.Fatal("password leaked onto stdio pipes")
	}

	cancel()
	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("stdio IO run did not stop")
	}
}

func TestStdioMissingActorFailsSafely(t *testing.T) {
	t.Parallel()
	s := mutationServer(t, mutationServices(newFakeUsers(), newFakeGroups(), &fakeBind{}), nil)
	srvT, cliT := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = s.Run(ctx, srvT) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "labldap-stdio-test", Version: "v0.0.1"}, nil)
	sess, err := client.Connect(ctx, cliT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: ToolCapabilities})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("stdio without credentials must not run tools")
	}
}
