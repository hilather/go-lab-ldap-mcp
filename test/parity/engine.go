package parity

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sort"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
)

// Control / extended-op OIDs used by the harness (contract C1/C9).
const (
	oidPagedResults  = "1.2.840.113556.1.4.319"
	oidAssertion     = "1.3.6.1.1.12"
	oidStartTLS      = "1.3.6.1.4.1.1466.20037"
	oidWhoAmI        = "1.3.6.1.4.1.4203.1.11.3"
	oidPasswordMod46 = "1.3.6.1.4.1.4203.1.7.1" // RFC 3062 — Excluded (E3)
)

// dialSpec describes one connection attempt: transport, trust material,
// and the bind to perform. noBind leaves the connection in the pre-bind
// (anonymous wire) state without sending a BindRequest at all.
type dialSpec struct {
	ldaps    bool
	startTLS bool
	badCA    bool
	badName  bool
	bindDN   string
	bindPass string
	noBind   bool
}

// engine is the dual-engine abstraction: a running directory the harness
// can dial. The native engine runs in-process (native.go); the 389 oracle
// runs in Docker behind the integration build tag (oracle.go).
type engine interface {
	name() string
	// dial connects, optionally upgrades with StartTLS, and binds.
	// Errors are returned, never fatal: bind/transport failure codes are
	// themselves Contract data points.
	dial(t *testing.T, spec dialSpec) (*ldap.Conn, error)
	// dm returns a Directory-Manager-bound connection over LDAPS.
	dm(t *testing.T) *ldap.Conn
	// dmSecret is the engine's Directory Manager password (the native
	// fixture constant; the oracle's harness-generated secret). It is
	// used only on the wire, never recorded in outcomes or the ledger.
	dmSecret() string
	// addr returns the host:port the engine listens on, for the raw-wire
	// probes go-ldap cannot express (anonymous simple bind, LDAPv2 bind).
	addr(ldaps bool) string
	// clientTLS is the engine's normal client TLS config (fixture CA for
	// native, container CA + hostname for the oracle) for raw-wire TLS.
	clientTLS() *tls.Config
	// caFile writes the engine's TLS CA to a temp file for ldapclient.
	caFile(t *testing.T) string
	// serverName is the TLS server name clients must present.
	serverName() string
	close(t *testing.T)
}

// dialCode performs a dial attempt and captures only its result code
// (0 on success, -1 on transport failure), closing the connection.
func dialCode(t *testing.T, e engine, spec dialSpec) opOutcome {
	t.Helper()
	conn, err := e.dial(t, spec)
	if conn != nil {
		conn.Close()
	}
	return codeOutcome(err)
}

// mustDial returns a bound connection or fails the case.
func mustDial(t *testing.T, e engine, spec dialSpec) *ldap.Conn {
	t.Helper()
	conn, err := e.dial(t, spec)
	if err != nil {
		t.Fatalf("parity: %s dial %+v: %v", e.name(), spec, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// userSpec is the common "end user over LDAPS" dial.
func userSpec(dn, password string) dialSpec {
	return dialSpec{ldaps: true, bindDN: dn, bindPass: password}
}

// assertionControl builds the RFC 4528 control. The control value is the
// BER-encoded SearchFilter (RFC 4528 section 2); ldap.CompileFilter
// produces exactly that packet.
func assertionControl(t *testing.T, filter string, critical bool) ldap.Control {
	t.Helper()
	fp, err := ldap.CompileFilter(filter)
	if err != nil {
		t.Fatalf("parity: compile assertion filter %q: %v", filter, err)
	}
	return ldap.NewControlString(oidAssertion, critical, string(fp.Bytes()))
}

// whoami invokes the RFC 4532 WhoAmI extended op and captures the code
// plus the authzid value. An empty value and an absent value are distinct
// on the wire (CAND-20), so absence is rendered as "<absent>".
func whoami(conn *ldap.Conn) opOutcome {
	res, err := conn.Extended(ldap.NewExtendedRequest(oidWhoAmI, nil))
	out := opOutcome{Code: ldapCode(err)}
	if out.Code != 0 {
		return out
	}
	if res == nil || res.Value == nil {
		out.Value = "<absent>"
		return out
	}
	out.Value = string(res.Value.ByteValue)
	if out.Value == "" {
		// go-ldap leaves ByteValue nil when the packet carried its payload
		// in the Data buffer only.
		out.Value = res.Value.Data.String()
	}
	if out.Value == "" {
		out.Value = "<empty>"
	}
	return out
}

// pagedPage issues one page of a Simple Paged Results search with an
// explicit cookie and captures the code plus this page's canonical
// entries, returning the server-issued cookie for the next page. Cookie
// bytes themselves are engine-specific (HMAC-signed on native) and are
// never recorded.
func pagedPage(conn *ldap.Conn, base, filter string, size uint32, cookie []byte) (opOutcome, []byte) {
	ctrl := ldap.NewControlPaging(size)
	if len(cookie) > 0 {
		ctrl.SetCookie(cookie)
	}
	req := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, []string{"cn"}, []ldap.Control{ctrl})
	res, err := conn.Search(req)
	out := opOutcome{Code: ldapCode(err)}
	var next []byte
	if res != nil {
		out.Entries = canonicalizeAll(res.Entries)
		if rc := ldap.FindControl(res.Controls, oidPagedResults); rc != nil {
			if pc, ok := rc.(*ldap.ControlPaging); ok {
				next = pc.Cookie
			}
		}
	}
	return out, next
}

// pagedWalk drives a full paged search to completion (or the first error)
// and aggregates: one outcome holding the per-page result codes as the
// Value and the union of all pages as canonical entries. Search result
// order — and therefore page composition — is not Contract, so per-page
// sets are never compared.
func pagedWalk(conn *ldap.Conn, base, filter string, size uint32, maxPages int) opOutcome {
	var codes []byte
	var all []canonEntry
	var cookie []byte
	for page := 0; page < maxPages; page++ {
		po, next := pagedPage(conn, base, filter, size, cookie)
		codes = append(codes, byte(po.Code))
		all = append(all, po.Entries...)
		cookie = next
		if po.Code != 0 || len(cookie) == 0 {
			break
		}
	}
	sortCanon(all)
	return opOutcome{Code: 0, Entries: all, Value: fmt.Sprintf("codes=%v pages=%d", codes, len(codes))}
}

// sortCanon re-sorts an aggregated entry set (pagedWalk unions pages).
func sortCanon(entries []canonEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].DN < entries[j].DN })
}

// rawBind hand-builds a simple BindRequest over a bare connection,
// reporting the server's result code. go-ldap refuses client-side to
// send an anonymous simple bind (empty password) or any LDAPv2 bind, so
// those Contract/Delta observations (CAND-1, CAND-10 version check)
// need the wire-level form. It never fatal-errors: a refusal or a torn
// connection is itself a recorded outcome.
func rawBind(t *testing.T, c *caseCtx, useTLS bool, version int64, dn, pass string) opOutcome {
	t.Helper()
	nc, err := net.DialTimeout("tcp", c.e.addr(useTLS), 5*time.Second)
	if err != nil {
		t.Fatalf("parity: raw dial: %v", err)
	}
	defer nc.Close()
	conn := net.Conn(nc)
	if useTLS {
		tc := tls.Client(nc, c.e.clientTLS())
		if err := tc.Handshake(); err != nil {
			t.Fatalf("parity: raw TLS handshake: %v", err)
		}
		conn = tc
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	msg := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "Message ID"))
	bind := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.TagEOC, nil, "Bind Request") // [APPLICATION 0]
	bind.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, version, "Version"))
	bind.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "Name"))
	bind.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, pass, "Simple Authentication"))
	msg.AppendChild(bind)

	if _, err := conn.Write(msg.Bytes()); err != nil {
		return opOutcome{Code: -1, Note: "write-failed"}
	}
	pkt, err := ber.ReadPacket(conn)
	switch {
	case err == io.EOF:
		return opOutcome{Code: -1, Note: "closed-without-response"}
	case err != nil:
		return opOutcome{Code: -1, Note: "closed-after-error"}
	}
	// BindResponse: [APPLICATION 1] with resultCode as first child.
	if len(pkt.Children) < 2 || len(pkt.Children[1].Children) == 0 {
		return opOutcome{Code: -1, Note: "malformed-response"}
	}
	code := pkt.Children[1].Children[0].Value.(int64)
	return opOutcome{Code: int(code)}
}

// rawSASLBind hand-builds a BindRequest carrying a SASL (choice [3])
// credential over a bare connection — go-ldap has no SASL client, and the
// Excluded-tier check (E2) needs the server's wire behavior, not a
// successful bind. It reports the observed outcome: a protocolError
// notice of disconnection, or the server closing the connection; both
// prove SASL is unreachable.
func rawSASLBind(t *testing.T, addr string) opOutcome {
	t.Helper()
	nc, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("parity: raw dial %s: %v", addr, err)
	}
	defer nc.Close()
	_ = nc.SetDeadline(time.Now().Add(5 * time.Second))

	msg := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "Message ID"))
	bind := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.TagEOC, nil, "Bind Request") // [APPLICATION 0]
	bind.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	bind.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Name"))
	sasl := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "Sasl Credentials")
	sasl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "PLAIN", "Mechanism"))
	sasl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "\x00parity\x00nop", "Credentials"))
	bind.AppendChild(sasl)
	msg.AppendChild(bind)

	if _, err := nc.Write(msg.Bytes()); err != nil {
		return opOutcome{Code: -1, Note: "write-failed"}
	}
	pkt, err := ber.ReadPacket(nc)
	switch {
	case err == io.EOF:
		return opOutcome{Code: -1, Note: "closed-without-response"}
	case err != nil:
		return opOutcome{Code: -1, Note: "closed-after-error"}
	default:
		// A notice of disconnection is an ExtendedResponse carrying
		// protocolError; any well-formed rejection proves the point.
		_ = pkt
		return opOutcome{Code: 2, Note: "notice-of-disconnection"}
	}
}
