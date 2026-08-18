package ldapserver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// conn is one client connection. It owns the read loop, the per-connection
// outstanding-operation registry (for Abandon), the bound identity, and the
// pre-auth counters (ADR-0009 decision 10). All fields behind mu are
// accessed through the small helpers so the concurrent op goroutines never
// touch them bare.
type conn struct {
	srv   *Server
	nc    net.Conn
	codec Codec
	// isTLS is true on the LDAPS listener or after a successful StartTLS
	// upgrade. It is read and written only on the serve goroutine (bind
	// and StartTLS both run inline), so it needs no lock; upgradeTLS
	// flips it under mu purely to stay adjacent to the nc swap.
	isTLS  bool
	remote string

	// sem bounds outstanding (dispatched, not yet completed) operations.
	sem chan struct{}
	// writeMu serializes all outbound PDUs.
	writeMu sync.Mutex

	mu           sync.Mutex
	subj         Subject
	lastActivity time.Time
	failedAuth   int
	inflight     map[int64]context.CancelFunc

	ctx    context.Context
	cancel context.CancelFunc
}

// newConn wraps an accepted connection. ctx is the server serve context; the
// returned conn derives its own cancelable child so closing one connection
// cancels its in-flight operations without touching the server.
func (s *Server) newConn(ctx context.Context, nc net.Conn, isTLS bool) *conn {
	cctx, cancel := context.WithCancel(ctx)
	remote := ""
	if nc != nil && nc.RemoteAddr() != nil {
		remote = nc.RemoteAddr().String()
	}
	return &conn{
		srv:          s,
		nc:           nc,
		codec:        s.opts.Codec,
		isTLS:        isTLS,
		remote:       remote,
		sem:          make(chan struct{}, s.opts.Limits.MaxOutstandingOps),
		lastActivity: time.Now(),
		inflight:     map[int64]context.CancelFunc{},
		ctx:          cctx,
		cancel:       cancel,
	}
}

// close cancels in-flight work and closes the socket. It is idempotent.
func (c *conn) close() {
	c.cancel()
	if nc := c.netConn(); nc != nil {
		_ = nc.Close()
	}
}

// netConn returns the current transport. StartTLS replaces it mid-life, so
// callers on goroutines other than the read loop must go through here.
func (c *conn) netConn() net.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nc
}

// serve is the connection read loop: decode one LDAPMessage at a time,
// handle synchronous control operations (bind, unbind, abandon) inline, and
// dispatch the rest to bounded worker goroutines.
func (c *conn) serve() {
	defer func() {
		c.close()
		c.srv.removeConn(c)
	}()
	for {
		if c.ctx.Err() != nil {
			return
		}
		// Read the transport each iteration: a StartTLS upgrade swaps it.
		nc := c.netConn()
		if nc == nil {
			return
		}
		if err := nc.SetReadDeadline(c.nextReadDeadline()); err != nil {
			return
		}
		msg, err := c.codec.ReadMessage(c.ctx, nc)
		if err != nil {
			c.handleReadError(err)
			return
		}
		c.touch()
		switch op := msg.Op.(type) {
		case *BindRequest:
			// Bind runs inline so the read loop observes the new identity
			// before dispatching any subsequent request on this connection.
			if !c.srv.handleBind(c.ctx, c, msg, op) {
				return
			}
		case *UnbindRequest:
			// Unbind closes the connection; no response PDU (RFC 4511 4.3).
			return
		case *AbandonRequest:
			c.abandon(op.MessageID)
		case *ExtendedRequest:
			if op.Name == OIDStartTLS {
				// StartTLS runs inline like bind: after the success
				// response the read loop must read TLS records from the
				// upgraded transport, so no other message may be
				// dispatched between the response and the handshake.
				if !c.srv.handleStartTLS(c.ctx, c, msg, op) {
					return
				}
				continue
			}
			c.spawnOp(msg)
		default:
			c.spawnOp(msg)
		}
	}
}

// handleReadError decides whether the peer gets a notice of disconnection
// before the connection closes. Errors never echo wire content.
func (c *conn) handleReadError(err error) {
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		// Clean close or truncated final message: nothing to send.
	case c.ctx.Err() != nil:
		// Server shutting down or connection closed locally.
	case errors.Is(err, ErrPDUTooLarge):
		c.sendNoticeOfDisconnection(ResultProtocolError, "PDU exceeds size limit")
	case errors.Is(err, ErrMalformedPDU), errors.Is(err, ErrUnsupportedOp):
		c.sendNoticeOfDisconnection(ResultProtocolError, "malformed or unsupported PDU")
	default:
		// Network and deadline errors (including read/idle timeouts):
		// close silently; the peer already stopped listening.
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() {
			c.srv.opts.Logger.LogAttrs(c.ctx, slog.LevelDebug, "connection closed on read deadline",
				slog.String("remote", c.remote))
			return
		}
		c.srv.opts.Logger.LogAttrs(c.ctx, slog.LevelDebug, "connection read failed",
			slog.String("remote", c.remote), slog.String("error", err.Error()))
	}
}

// nextReadDeadline combines the read timeout with the idle timeout: a
// connection that produced no traffic for IdleTimeout is closed even when
// ReadTimeout is longer (ADR-0009 decision 10).
func (c *conn) nextReadDeadline() time.Time {
	l := c.srv.opts.Limits
	d := time.Now().Add(l.ReadTimeout)
	c.mu.Lock()
	last := c.lastActivity
	c.mu.Unlock()
	if idle := last.Add(l.IdleTimeout); idle.Before(d) {
		d = idle
	}
	return d
}

func (c *conn) touch() {
	c.mu.Lock()
	c.lastActivity = time.Now()
	c.mu.Unlock()
}

// subject returns the currently bound identity.
func (c *conn) subject() Subject {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.subj
}

// setSubject replaces the bound identity.
func (c *conn) setSubject(s Subject) {
	c.mu.Lock()
	c.subj = s
	c.mu.Unlock()
}

// recordFailedAuth increments the failed-bind counter and reports the total.
func (c *conn) recordFailedAuth() int {
	c.mu.Lock()
	c.failedAuth++
	n := c.failedAuth
	c.mu.Unlock()
	return n
}

// resetFailedAuth clears the failed-bind counter after a successful bind
// so a later typo cannot consume a pre-success budget.
func (c *conn) resetFailedAuth() {
	c.mu.Lock()
	c.failedAuth = 0
	c.mu.Unlock()
}

// outstandingCount reports in-flight dispatched operations. Bind and
// StartTLS run inline and are not counted here.
func (c *conn) outstandingCount() int {
	c.mu.Lock()
	n := len(c.inflight)
	c.mu.Unlock()
	return n
}

// spawnOp dispatches one request to a worker goroutine under the
// outstanding-operations semaphore and the in-flight registry.
func (c *conn) spawnOp(msg *Message) {
	select {
	case c.sem <- struct{}{}:
	default:
		// Outstanding-op ceiling: reject the operation, keep the
		// connection (ADR-0009 decision 10).
		c.sendResult(msg.ID, responseFor(msg.Op, Result{
			Code:              ResultBusy,
			DiagnosticMessage: "too many outstanding operations",
		}))
		c.srv.metrics().ObserveOperation(opName(msg.Op), ResultBusy)
		return
	}
	opCtx, cancel := context.WithCancel(c.ctx)
	if !c.registerInflight(msg.ID, cancel) {
		cancel()
		<-c.sem
		c.sendResult(msg.ID, responseFor(msg.Op, Result{
			Code:              ResultProtocolError,
			DiagnosticMessage: "duplicate message ID in flight",
		}))
		c.srv.metrics().ObserveOperation(opName(msg.Op), ResultProtocolError)
		return
	}
	go func() {
		defer func() {
			c.unregisterInflight(msg.ID)
			cancel()
			<-c.sem
			c.touch()
		}()
		c.srv.dispatchOp(opCtx, c, msg)
	}()
}

// registerInflight records the cancel func for msgID. It fails on a
// duplicate in-flight ID (RFC 4511 4.1.1: message IDs cannot be reused
// while outstanding).
func (c *conn) registerInflight(msgID int64, cancel context.CancelFunc) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, dup := c.inflight[msgID]; dup {
		return false
	}
	c.inflight[msgID] = cancel
	return true
}

func (c *conn) unregisterInflight(msgID int64) {
	c.mu.Lock()
	delete(c.inflight, msgID)
	c.mu.Unlock()
}

// abandon cancels the in-flight operation with the given message ID, if
// any. The abandoned operation sends no response (RFC 4511 4.11).
func (c *conn) abandon(msgID int64) {
	c.mu.Lock()
	cancel := c.inflight[msgID]
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// send writes one message under the write lock with the write deadline. A
// nil nc (unit tests driving handlers without a socket) drops the write.
func (c *conn) send(m *Message) error {
	nc := c.netConn()
	if nc == nil {
		return nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := nc.SetWriteDeadline(time.Now().Add(c.srv.opts.Limits.WriteTimeout)); err != nil {
		return err
	}
	if err := c.codec.WriteMessage(c.ctx, nc, m); err != nil {
		c.srv.opts.Logger.LogAttrs(c.ctx, slog.LevelDebug, "write failed",
			slog.String("remote", c.remote), slog.String("error", err.Error()))
		return err
	}
	return nil
}

// sendResult writes a response message carrying op.
func (c *conn) sendResult(id int64, op Operation) error {
	return c.send(&Message{ID: id, Op: op})
}

// sendNoticeOfDisconnection makes a best-effort RFC 4511 section 4.4.1
// unsolicited notice before a server-initiated close. The diagnostic is
// always a static string.
func (c *conn) sendNoticeOfDisconnection(code ResultCode, diag string) {
	_ = c.send(&Message{ID: 0, Op: &ExtendedResponse{
		Result: Result{Code: code, DiagnosticMessage: diag},
		Name:   OIDNoticeOfDisconnection,
	}})
}

// responseFor maps a request operation to its typed response shell.
func responseFor(op Operation, res Result) Operation {
	switch op.OpCode() {
	case OpBindRequest:
		return &BindResponse{Result: res}
	case OpSearchRequest:
		return &SearchResultDone{Result: res}
	case OpModifyRequest:
		return &ModifyResponse{Result: res}
	case OpAddRequest:
		return &AddResponse{Result: res}
	case OpDeleteRequest:
		return &DeleteResponse{Result: res}
	case OpModifyDNRequest:
		return &ModifyDNResponse{Result: res}
	case OpCompareRequest:
		return &CompareResponse{Result: res}
	case OpExtendedRequest:
		return &ExtendedResponse{Result: res}
	default:
		return &ExtendedResponse{Result: res}
	}
}

// opName returns a bounded-cardinality operation label for logs/metrics.
func opName(op Operation) string {
	switch op.OpCode() {
	case OpBindRequest:
		return "bind"
	case OpUnbindRequest:
		return "unbind"
	case OpSearchRequest:
		return "search"
	case OpModifyRequest:
		return "modify"
	case OpAddRequest:
		return "add"
	case OpDeleteRequest:
		return "delete"
	case OpModifyDNRequest:
		return "modifydn"
	case OpCompareRequest:
		return "compare"
	case OpAbandonRequest:
		return "abandon"
	case OpExtendedRequest:
		return "extended"
	default:
		return "unknown"
	}
}
