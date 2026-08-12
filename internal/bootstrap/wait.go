package bootstrap

import (
	"context"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// WaitRequest is the engine-wait input. Passwords are Secret-wrapped.
type WaitRequest struct {
	// LDAPURL, when set, is the full ldap(s)://host:port used for DialURL.
	LDAPURL     string
	Host        string
	LDAPPort    int
	LDAPSPort   int
	UseLDAPS    bool
	StartTLS    bool
	Insecure    bool
	CAFile      string
	BindDN      string
	Password    observability.Secret
	DialTimeout time.Duration
	Deadline    time.Duration
}

// WaitResult is secret-free wait output.
type WaitResult struct {
	Transport      string
	NamingContexts int
}

// Waiter waits for the directory engine and binds as Directory Manager.
type Waiter interface {
	Wait(ctx context.Context, req WaitRequest) (WaitResult, error)
}

const defaultBindDN = "cn=Directory Manager"
