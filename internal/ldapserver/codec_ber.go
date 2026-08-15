package ldapserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// Compile-time satisfaction of the pinned Codec interface (T-122/T-124).
var _ Codec = (*BERCodec)(nil)

// Codec-domain conditions. Decode failures are deliberately generic: a
// pre-auth parser must not echo untrusted protocol bytes back into logs or
// diagnostics, so error strings carry only static context, offsets, tags,
// and lengths — never DNs, attribute values, or credential material.
var (
	// ErrPDUTooLarge marks a PDU beyond MaxPDUBytes. On reads it is
	// detected from the length prefix before the body buffer is allocated.
	ErrPDUTooLarge = errors.New("ldapserver: PDU exceeds MaxPDUBytes")
	// ErrMalformedPDU marks structurally invalid BER or LDAPMessage shapes.
	ErrMalformedPDU = errors.New("ldapserver: malformed LDAP PDU")
	// ErrUnsupportedOp marks well-formed protocolOps outside the pinned
	// model (SASL binds, extensible match, intermediate responses, ...).
	ErrUnsupportedOp = errors.New("ldapserver: unsupported protocol operation")
)

// Default decode budgets. LDAP messages are shallow: SearchRequest nesting
// is message(1) + op(2) + one level per filter node, so 64 TLV levels
// admits ~60-deep filters, far beyond any legitimate client. A 1 MiB PDU
// can hold ~500k two-byte TLVs; 100k elements bounds decode allocations to
// tens of MiB worst case while leaving room for large group Add requests.
const (
	defaultMaxDepth    = 64
	defaultMaxElements = 100_000
)

// BERCodecOptions tunes the concrete codec. A zero or negative field takes
// the documented default.
type BERCodecOptions struct {
	// MaxPDUBytes is the per-PDU ceiling including the header (ADR-0009
	// decision 10). Default: DefaultLimits().MaxPDUBytes. It is enforced on
	// reads from the length prefix, before body allocation, and on writes
	// after encoding so a defective handler cannot emit a giant PDU.
	MaxPDUBytes int
	// MaxDepth is the TLV nesting budget. Default: 64.
	MaxDepth int
	// MaxElements is the total TLV element budget per PDU. Default: 100000.
	MaxElements int
}

// BERCodec is the production Codec: BER encode/decode of LDAPMessage via
// github.com/go-asn1-ber/asn1-ber (ADR-0009 decision 9 — a from-scratch BER
// codec is rejected). The framing layer and TLV pre-scan are not a second
// BER implementation: they enforce length/depth/element budgets that
// asn1-ber exposes only as process-wide mutable globals
// (ber.MaxPacketLengthBytes, ber.MaxNestingDepth), which a multi-connection
// pre-auth server cannot safely treat as its only defense. Value decoding
// and all encoding go through asn1-ber.
type BERCodec struct {
	maxPDUBytes int
	maxDepth    int
	maxElements int
}

// NewBERCodec returns a BERCodec with normalized options. The codec is
// immutable and safe for concurrent use.
func NewBERCodec(opts BERCodecOptions) *BERCodec {
	c := &BERCodec{
		maxPDUBytes: opts.MaxPDUBytes,
		maxDepth:    opts.MaxDepth,
		maxElements: opts.MaxElements,
	}
	if c.maxPDUBytes <= 0 {
		c.maxPDUBytes = DefaultLimits().MaxPDUBytes
	}
	if c.maxDepth <= 0 {
		c.maxDepth = defaultMaxDepth
	}
	if c.maxElements <= 0 {
		c.maxElements = defaultMaxElements
	}
	return c
}

// MaxPDUBytes reports the configured per-PDU size ceiling.
func (c *BERCodec) MaxPDUBytes() int { return c.maxPDUBytes }

// maxHeaderBytes bounds a definite-form BER header: 1 identifier octet
// (LDAPMessage is always 0x30, so no high-tag form) + 1 length octet +
// up to 8 long-form length octets.
const maxHeaderBytes = 10

// ReadMessage reads exactly one LDAPMessage from r.
//
// The length prefix is validated against MaxPDUBytes before the body buffer
// is allocated, so a hostile length claim cannot grow allocations beyond
// the configured ceiling. A structural pre-scan then enforces the depth and
// element budgets before asn1-ber performs the actual decode.
//
// Returns a wrapped io.EOF when the peer closes between messages, a wrapped
// io.ErrUnexpectedEOF when the stream ends mid-message, and a wrapped
// ErrPDUTooLarge / ErrMalformedPDU / ErrUnsupportedOp otherwise. Blocking
// reads are released by caller-set deadlines (T-125); ctx is honored
// between framing steps.
func (c *BERCodec) ReadMessage(ctx context.Context, r io.Reader) (*Message, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	buf, err := c.readFrame(r)
	if err != nil {
		return nil, err
	}
	// The framed buffer holds a copy of any bind password; scrub it once the
	// message is decoded (decoded fields are independent copies).
	defer clear(buf)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := scanTLVs(buf, c.maxDepth, c.maxElements); err != nil {
		return nil, err
	}
	pkt, err := ber.DecodePacketErr(buf)
	if err != nil {
		// The library error text can embed untrusted runes; do not relay it.
		return nil, fmt.Errorf("ldapserver: read message: ber decode: %w", ErrMalformedPDU)
	}
	return decodeMessage(pkt)
}

// readFrame consumes exactly one BER TLV (the LDAPMessage) from r and
// returns header+body as one bounded buffer.
func (c *BERCodec) readFrame(r io.Reader) ([]byte, error) {
	var hdr [maxHeaderBytes]byte
	if _, err := io.ReadFull(r, hdr[:2]); err != nil {
		switch {
		case errors.Is(err, io.EOF):
			// No bytes of a new message: clean connection close.
			return nil, fmt.Errorf("ldapserver: read message: %w", io.EOF)
		case errors.Is(err, io.ErrUnexpectedEOF):
			return nil, fmt.Errorf("ldapserver: read message header: %w", io.ErrUnexpectedEOF)
		default:
			// Network failure mid-header: preserve the underlying error.
			return nil, fmt.Errorf("ldapserver: read message header: %w", err)
		}
	}
	if hdr[0] != 0x30 {
		// LDAPMessage ::= SEQUENCE, always universal/constructed/16.
		return nil, fmt.Errorf("ldapserver: read message: first octet 0x%02x is not a SEQUENCE: %w", hdr[0], ErrMalformedPDU)
	}
	hdrLen := 2
	var contentLen uint64
	switch lb := hdr[1]; {
	case lb == 0x80:
		return nil, fmt.Errorf("ldapserver: read message: indefinite length form: %w", ErrMalformedPDU)
	case lb == 0xff:
		return nil, fmt.Errorf("ldapserver: read message: invalid length octet 0xff: %w", ErrMalformedPDU)
	case lb&0x80 == 0:
		contentLen = uint64(lb)
	default:
		n := int(lb & 0x7f)
		if n > 8 {
			return nil, fmt.Errorf("ldapserver: read message: long-form length of %d octets overflows: %w", n, ErrMalformedPDU)
		}
		if _, err := io.ReadFull(r, hdr[2:2+n]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, fmt.Errorf("ldapserver: read message length: %w", io.ErrUnexpectedEOF)
			}
			return nil, fmt.Errorf("ldapserver: read message length: %w", err)
		}
		hdrLen += n
		for _, b := range hdr[2 : 2+n] {
			contentLen = contentLen<<8 | uint64(b)
		}
	}
	// Enforce the ceiling on the whole PDU (header included) BEFORE the
	// body allocation: total is derived solely from the header bytes
	// already read.
	total := uint64(hdrLen) + contentLen
	if total > uint64(c.maxPDUBytes) {
		return nil, fmt.Errorf("ldapserver: read message: PDU length %d exceeds limit %d: %w", total, c.maxPDUBytes, ErrPDUTooLarge)
	}
	buf := make([]byte, int(total)) // total <= maxPDUBytes, an int
	copy(buf, hdr[:hdrLen])
	if _, err := io.ReadFull(r, buf[hdrLen:]); err != nil {
		clear(buf)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("ldapserver: read message body: %w", io.ErrUnexpectedEOF)
		}
		return nil, fmt.Errorf("ldapserver: read message body: %w", err)
	}
	return buf, nil
}

// scanTLVs validates the TLV structure of buf iteratively (explicit stack,
// no recursion): exactly one top-level element, definite lengths inside
// their enclosing values, no end-of-content markers, and the depth and
// element budgets. It decodes no values; ber.DecodePacketErr performs the
// real decode afterwards.
func scanTLVs(buf []byte, maxDepth, maxElements int) error {
	stack := make([]int, 0, 16) // end offsets of enclosing constructed values
	elements := 0
	off := 0
	for {
		for len(stack) > 0 && off == stack[len(stack)-1] {
			stack = stack[:len(stack)-1]
		}
		if off == len(buf) {
			if len(stack) != 0 {
				return fmt.Errorf("ldapserver: read message: truncated constructed value: %w", ErrMalformedPDU)
			}
			return nil
		}
		if len(stack) == 0 && elements > 0 {
			return fmt.Errorf("ldapserver: read message: trailing data after LDAPMessage: %w", ErrMalformedPDU)
		}
		b := buf[off]
		off++
		class, constructed := b&0xc0, b&0x20 != 0
		tag := uint64(b & 0x1f)
		if tag == 0x1f {
			tag = 0
			for i := 0; ; i++ {
				if i >= 9 {
					return fmt.Errorf("ldapserver: read message: high-tag overflow: %w", ErrMalformedPDU)
				}
				if off >= len(buf) {
					return fmt.Errorf("ldapserver: read message: truncated tag: %w", ErrMalformedPDU)
				}
				tb := buf[off]
				off++
				tag = tag<<7 | uint64(tb&0x7f)
				if i == 0 && tag == 0 {
					return fmt.Errorf("ldapserver: read message: non-minimal high tag: %w", ErrMalformedPDU)
				}
				if tb&0x80 == 0 {
					break
				}
			}
		}
		if class == 0 && !constructed && tag == 0 {
			return fmt.Errorf("ldapserver: read message: unexpected end-of-content: %w", ErrMalformedPDU)
		}
		if off >= len(buf) {
			return fmt.Errorf("ldapserver: read message: truncated length: %w", ErrMalformedPDU)
		}
		lb := buf[off]
		off++
		var length int
		switch {
		case lb == 0x80:
			return fmt.Errorf("ldapserver: read message: indefinite length form: %w", ErrMalformedPDU)
		case lb == 0xff:
			return fmt.Errorf("ldapserver: read message: invalid length octet 0xff: %w", ErrMalformedPDU)
		case lb&0x80 == 0:
			length = int(lb)
		default:
			n := int(lb & 0x7f)
			if n > 8 {
				return fmt.Errorf("ldapserver: read message: long-form length of %d octets overflows: %w", n, ErrMalformedPDU)
			}
			if off+n > len(buf) {
				return fmt.Errorf("ldapserver: read message: truncated length: %w", ErrMalformedPDU)
			}
			var v uint64
			for _, x := range buf[off : off+n] {
				v = v<<8 | uint64(x)
			}
			off += n
			if v > uint64(len(buf)) {
				return fmt.Errorf("ldapserver: read message: content length exceeds PDU: %w", ErrMalformedPDU)
			}
			length = int(v)
		}
		parentEnd := len(buf)
		if len(stack) > 0 {
			parentEnd = stack[len(stack)-1]
		}
		end := off + length // length <= len(buf), so no int overflow
		if end > parentEnd {
			return fmt.Errorf("ldapserver: read message: content exceeds enclosing value: %w", ErrMalformedPDU)
		}
		elements++
		if elements > maxElements {
			return fmt.Errorf("ldapserver: read message: element budget %d exceeded: %w", maxElements, ErrMalformedPDU)
		}
		if constructed {
			if len(stack)+1 > maxDepth {
				return fmt.Errorf("ldapserver: read message: depth budget %d exceeded: %w", maxDepth, ErrMalformedPDU)
			}
			stack = append(stack, end)
			continue // descend: off is already at the child's first octet
		}
		off = end
	}
}

// WriteMessage encodes m and writes it to w. Encoded scratch buffers that
// may carry a bind password are scrubbed before return. Blocking writes are
// released by caller-set deadlines (T-125); ctx is honored before and
// during the write loop.
func (c *BERCodec) WriteMessage(ctx context.Context, w io.Writer, m *Message) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	buf, err := encodeMessage(m)
	if err != nil {
		return err
	}
	defer clear(buf)
	if len(buf) > c.maxPDUBytes {
		return fmt.Errorf("ldapserver: write message: PDU length %d exceeds limit %d: %w", len(buf), c.maxPDUBytes, ErrPDUTooLarge)
	}
	for len(buf) > 0 {
		n, werr := w.Write(buf)
		buf = buf[n:]
		if werr != nil {
			return fmt.Errorf("ldapserver: write message: %w", werr)
		}
		if n == 0 {
			return fmt.Errorf("ldapserver: write message: %w", io.ErrShortWrite)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return nil
}

// ZeroSecrets overwrites credential material carried by m. Callers zero a
// decoded BindRequest once authentication completes (T-126).
func ZeroSecrets(m *Message) {
	if m == nil {
		return
	}
	if br, ok := m.Op.(*BindRequest); ok {
		clear(br.Password)
		br.Password = nil
	}
}

// String redacts the password so a BindRequest is safe for %v and slog.
func (r *BindRequest) String() string {
	if r == nil {
		return "BindRequest<nil>"
	}
	return fmt.Sprintf("BindRequest{version:%d name:%q password:[redacted]}", r.Version, r.Name)
}

// GoString redacts the password so a BindRequest is safe for %#v.
func (r *BindRequest) GoString() string { return r.String() }

// packetInt reads a universal primitive INTEGER or ENUMERATED. asn1-ber
// leaves Value nil when the content exceeds 8 bytes, and zero-length
// integer content is not valid BER, so both fail closed here.
func packetInt(p *ber.Packet) (int64, error) {
	n := len(p.Data.Bytes())
	if n == 0 || n > 8 {
		return 0, fmt.Errorf("integer content of %d octets: %w", n, ErrMalformedPDU)
	}
	v, ok := p.Value.(int64)
	if !ok {
		return 0, fmt.Errorf("integer value: %w", ErrMalformedPDU)
	}
	return v, nil
}

// intInRange decodes p as an integer and bounds it to [lo, hi] (message
// IDs, limits, and enumerations are 32-bit on the wire).
func intInRange(p *ber.Packet, lo, hi int64, what string) (int64, error) {
	v, err := packetInt(p)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", what, err)
	}
	if v < lo || v > hi {
		return 0, fmt.Errorf("%s out of range: %w", what, ErrMalformedPDU)
	}
	return v, nil
}

// maxInt32 is the RFC 4511 MessageID / limit ceiling.
const maxInt32 = int64(math.MaxInt32)
