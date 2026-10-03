package store

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver"
	bolt "go.etcd.io/bbolt"
)

var _ ldapserver.SearchWalker = readTx{}

// WalkSearch uses a cursor per ancestor, rather than collecting every entry
// or every sibling ID. Working memory therefore scales with tree depth and
// the caller's bounded result set. A callback error stops decoding at once.
func (t readTx) WalkSearch(ctx context.Context, base config.DN, scope ldapserver.Scope, visit func(*ldapserver.Entry) error) error {
	root, err := t.Entry(ctx, base)
	if err != nil {
		return err
	}
	if scope == ldapserver.ScopeBaseObject || scope == ldapserver.ScopeWholeSubtree {
		if err := visit(root); err != nil {
			return err
		}
	}
	if scope == ldapserver.ScopeBaseObject {
		return nil
	}
	kids := t.tx.Bucket(bucketChildren).Bucket([]byte(base.FoldedKey()))
	if kids == nil {
		return nil
	}
	cursors := []*bolt.Cursor{kids.Cursor()}
	first := true
	for len(cursors) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		cursor := cursors[len(cursors)-1]
		var id []byte
		if first {
			id, _ = cursor.First()
			first = false
		} else {
			id, _ = cursor.Next()
		}
		if id == nil {
			cursors = cursors[:len(cursors)-1]
			continue
		}
		entry, err := t.entryByID(id)
		if err != nil {
			return err
		}
		if err := visit(entry); err != nil {
			return err
		}
		if scope != ldapserver.ScopeWholeSubtree {
			continue
		}
		dn, err := config.ParseDN(entry.DN)
		if err != nil {
			return fmt.Errorf("store: search walk: invalid stored DN")
		}
		if children := t.tx.Bucket(bucketChildren).Bucket([]byte(dn.FoldedKey())); children != nil {
			cursors = append(cursors, children.Cursor())
			first = true
		}
	}
	return nil
}

// WalkEqual limits candidates to the safe non-DN posting families; each
// posting and entry is consumed only as the search callback requests it.
func (t readTx) WalkEqual(ctx context.Context, attr string, value []byte, visit func(*ldapserver.Entry) error) (bool, error) {
	spec, ok := indexedAttributes[strings.ToLower(attr)]
	if !ok || spec.dn {
		return false, nil
	}
	bucket := t.tx.Bucket([]byte(spec.bucket))
	if bucket == nil {
		return true, fmt.Errorf("store: indexed search: missing bucket")
	}
	prefix := append(normalizeIndexKey(spec, value), 0)
	cursor := bucket.Cursor()
	counter := ReadCounterFrom(ctx)
	for key, _ := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, _ = cursor.Next() {
		if err := ctx.Err(); err != nil {
			return true, err
		}
		norm, id, valid := parsePostingKey(key)
		if !valid || !bytes.Equal(norm, prefix[:len(prefix)-1]) {
			continue
		}
		if counter != nil {
			counter.addIndexRead()
			counter.AddEntryFetch()
		}
		entry, err := t.entryByID(uint64Bytes(id))
		if err != nil {
			return true, err
		}
		if err := visit(entry); err != nil {
			return true, err
		}
	}
	return true, nil
}
