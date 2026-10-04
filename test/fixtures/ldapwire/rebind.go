// Package ldapwire contains independent raw LDAP clients shared by oracle tests.
package ldapwire

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// RebindAuthorization observes sequential Compare, Bind and Compare codes.
// Credentials are used only on the wire and are never included in diagnostics.
func RebindAuthorization(parent context.Context, address string, config *tls.Config, dn, password, dmPassword string) ([3]int64, error) {
	return rebindAuthorization(parent, address, config, dn, password, dmPassword, false)
}

// PipelinedAuthorization requires anonymous access enabled but no Compare grant.
// Anonymous and Alice denial controls must both be exactly 50 before overlap.
func PipelinedAuthorization(parent context.Context, address string, config *tls.Config, dn, password, dmPassword string) ([3]int64, error) {
	return rebindAuthorization(parent, address, config, dn, password, dmPassword, true)
}

func rebindAuthorization(parent context.Context, address string, config *tls.Config, dn, password, dmPassword string, pipeline bool) ([3]int64, error) {
	var result [3]int64
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	c, err := (&tls.Dialer{Config: config}).DialContext(ctx, "tcp", address)
	if err != nil {
		return result, fmt.Errorf("rebind TLS dial: %w", err)
	}
	defer c.Close()
	deadline, _ := ctx.Deadline()
	if err = c.SetDeadline(deadline); err != nil {
		return result, err
	}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	packet := func(id int, op *ber.Packet) []byte {
		p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
		p.AppendChild(op)
		return p.Bytes()
	}
	bind := func(id int, name, secret string) []byte {
		p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0, nil, "")
		p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, ""))
		p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, ""))
		p.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, secret, ""))
		return packet(id, p)
	}
	compare := func(id int) []byte {
		p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 14, nil, "")
		p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, ""))
		a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "uid", ""))
		a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "alice", ""))
		p.AppendChild(a)
		return packet(id, p)
	}
	read := func() (int64, int64, error) {
		p, e := ber.ReadPacket(c)
		if e != nil {
			return 0, 0, fmt.Errorf("rebind read: %w", e)
		}
		if p.ClassType != ber.ClassUniversal || p.Tag != ber.TagSequence || len(p.Children) != 2 {
			return 0, 0, fmt.Errorf("invalid LDAP response envelope")
		}
		id, ok := p.Children[0].Value.(int64)
		if !ok || p.Children[0].Tag != ber.TagInteger {
			return 0, 0, fmt.Errorf("invalid response ID")
		}
		op := p.Children[1]
		tag := ber.Tag(15)
		if id == 2 || id == 4 {
			tag = 1
		}
		if op.ClassType != ber.ClassApplication || op.Tag != tag || len(op.Children) != 3 {
			return 0, 0, fmt.Errorf("invalid response shape for ID %d", id)
		}
		code, ok := op.Children[0].Value.(int64)
		if !ok || op.Children[0].Tag != ber.TagEnumerated {
			return 0, 0, fmt.Errorf("invalid result code for ID %d", id)
		}
		return id, code, nil
	}
	denialControl := func(id int) error {
		if _, err = c.Write(compare(id)); err != nil {
			return err
		}
		got, code, err := read()
		if err != nil {
			return err
		}
		if got != int64(id) || code != 50 {
			return fmt.Errorf("denial control ID=%d code=%d", got, code)
		}
		return nil
	}
	if pipeline {
		if err = denialControl(5); err != nil {
			return result, err
		}
	}
	if _, err = c.Write(bind(4, dn, password)); err != nil {
		return result, err
	}
	id, code, err := read()
	if err != nil {
		return result, err
	}
	if id != 4 || code != 0 {
		return result, fmt.Errorf("initial bind ID=%d code=%d", id, code)
	}
	if pipeline {
		if err = denialControl(6); err != nil {
			return result, err
		}
		if _, err = c.Write(append(compare(1), bind(2, "cn=Directory Manager", dmPassword)...)); err != nil {
			return result, err
		}
		seen := map[int64]bool{}
		for !seen[2] {
			id, code, err = read()
			if err != nil {
				return result, err
			}
			if id < 1 || id > 2 || seen[id] {
				return result, fmt.Errorf("unexpected response ID %d", id)
			}
			seen[id] = true
			result[id-1] = code
		}
		if result[1] != 0 {
			return result, fmt.Errorf("DM bind code=%d", result[1])
		}
		if _, err = c.Write(compare(3)); err != nil {
			return result, err
		}
		for len(seen) < 3 {
			id, code, err = read()
			if err != nil {
				return result, err
			}
			if id < 1 || id > 3 || seen[id] {
				return result, fmt.Errorf("unexpected response ID %d", id)
			}
			seen[id] = true
			result[id-1] = code
		}
		return result, nil
	}
	requests := [][]byte{compare(1), bind(2, "cn=Directory Manager", dmPassword), compare(3)}
	for index, request := range requests {
		if _, err = c.Write(request); err != nil {
			return result, err
		}
		id, code, err = read()
		if err != nil {
			return result, err
		}
		if id != int64(index+1) {
			return result, fmt.Errorf("unexpected response ID %d", id)
		}
		result[index] = code
		if index == 1 && code != 0 {
			return result, fmt.Errorf("DM bind code=%d", code)
		}
	}
	return result, nil
}
