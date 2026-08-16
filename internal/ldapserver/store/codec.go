package store

import (
	"errors"
	"fmt"

	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver"
)

// id2entry values use a versioned length-prefixed binary form:
//
//	byte    version (entryVersion)
//	uvarint DN length, DN bytes (canonical form)
//	uvarint attribute count, then per attribute:
//	  uvarint name length, name bytes
//	  uvarint value count, then per value: uvarint length, value bytes
//
// Decoding is defensive: every length is bounds-checked before slicing so
// a corrupt database surfaces an error instead of a panic.
const entryVersion = 1

var errCorruptEntry = errors.New("store: corrupt entry encoding")

func encodeEntry(e *ldapserver.Entry) ([]byte, error) {
	size := 1 + len(e.DN) + 8
	for _, a := range e.Attributes {
		size += len(a.Name) + 16
		for _, v := range a.Values {
			size += len(v) + 8
		}
	}
	buf := make([]byte, 0, size)
	buf = append(buf, entryVersion)
	buf = appendUvarint(buf, uint64(len(e.DN)))
	buf = append(buf, e.DN...)
	buf = appendUvarint(buf, uint64(len(e.Attributes)))
	for _, a := range e.Attributes {
		if a.Name == "" {
			return nil, fmt.Errorf("store: encode entry %q: attribute name is empty", e.DN)
		}
		buf = appendUvarint(buf, uint64(len(a.Name)))
		buf = append(buf, a.Name...)
		buf = appendUvarint(buf, uint64(len(a.Values)))
		for _, v := range a.Values {
			buf = appendUvarint(buf, uint64(len(v)))
			buf = append(buf, v...)
		}
	}
	return buf, nil
}

func decodeEntry(buf []byte) (*ldapserver.Entry, error) {
	r := &reader{buf: buf}
	version, err := r.byte()
	if err != nil {
		return nil, err
	}
	if version != entryVersion {
		return nil, fmt.Errorf("store: unsupported entry version %d", version)
	}
	dn, err := r.bytes()
	if err != nil {
		return nil, err
	}
	nAttrs, err := r.uvarint()
	if err != nil {
		return nil, err
	}
	if nAttrs > uint64(r.remaining()) {
		// Each attribute needs at least a name-length byte and a
		// value-count byte, so the count cannot exceed remaining bytes.
		return nil, errCorruptEntry
	}
	e := &ldapserver.Entry{DN: string(dn)}
	for i := uint64(0); i < nAttrs; i++ {
		name, err := r.bytes()
		if err != nil {
			return nil, err
		}
		if len(name) == 0 {
			return nil, errCorruptEntry
		}
		nVals, err := r.uvarint()
		if err != nil {
			return nil, err
		}
		if nVals > uint64(r.remaining()) {
			return nil, errCorruptEntry
		}
		attr := ldapserver.Attribute{Name: string(name)}
		for j := uint64(0); j < nVals; j++ {
			v, err := r.bytes()
			if err != nil {
				return nil, err
			}
			attr.Values = append(attr.Values, append([]byte(nil), v...))
		}
		e.Attributes = append(e.Attributes, attr)
	}
	if r.remaining() != 0 {
		return nil, errCorruptEntry
	}
	return e, nil
}

func appendUvarint(buf []byte, v uint64) []byte {
	var scratch [10]byte
	n := 0
	for v >= 0x80 {
		scratch[n] = byte(v) | 0x80
		v >>= 7
		n++
	}
	scratch[n] = byte(v)
	return append(buf, scratch[:n+1]...)
}

type reader struct {
	buf []byte
	off int
}

func (r *reader) remaining() int {
	return len(r.buf) - r.off
}

func (r *reader) byte() (byte, error) {
	if r.remaining() < 1 {
		return 0, errCorruptEntry
	}
	b := r.buf[r.off]
	r.off++
	return b, nil
}

func (r *reader) uvarint() (uint64, error) {
	var v uint64
	for i := 0; i < 10; i++ {
		b, err := r.byte()
		if err != nil {
			return 0, err
		}
		if b < 0x80 {
			if i == 9 && b > 1 {
				return 0, errCorruptEntry
			}
			return v | uint64(b)<<(7*i), nil
		}
		v |= uint64(b&0x7f) << (7 * i)
	}
	return 0, errCorruptEntry
}

func (r *reader) bytes() ([]byte, error) {
	n, err := r.uvarint()
	if err != nil {
		return nil, err
	}
	if n > uint64(r.remaining()) {
		return nil, errCorruptEntry
	}
	out := r.buf[r.off : r.off+int(n)]
	r.off += int(n)
	return out, nil
}
