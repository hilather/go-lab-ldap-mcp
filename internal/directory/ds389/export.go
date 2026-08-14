package ds389

import (
	"context"
	"io"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
)

// Export streams a deterministic LDIF of the managed suffix. It pages
// DNs first, then fetches one entry at a time so attributes are not
// all held in memory.
func (r *Runtime) Export(ctx context.Context, w io.Writer, opts directory.ExportOptions) error {
	if r == nil {
		return directory.ExportError("export", directory.FieldUnavailable, "runtime is not configured")
	}
	if w == nil {
		return directory.ExportError("export", directory.FieldUnavailable, "export writer is not configured")
	}
	opts = r.exportOpts(opts)
	dns, err := r.listExportDNs(ctx)
	if err != nil {
		return err
	}
	if opts.MaxEntries > 0 && len(dns) > opts.MaxEntries {
		return directory.ExportLimit("export.entries", "export entry limit exceeded")
	}
	enc := directory.NewEncoder(w, opts)
	for _, dn := range dns {
		if err := ctx.Err(); err != nil {
			return err
		}
		ent, err := r.readExportEntry(ctx, dn)
		if err != nil {
			if fieldOf(err) == directory.FieldNotFound {
				continue
			}
			return err
		}
		if err := enc.WriteEntry(ctx, ent); err != nil {
			return err
		}
	}
	return enc.Close()
}

func (r *Runtime) exportOpts(opts directory.ExportOptions) directory.ExportOptions {
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = r.cfg.ExportMaxEntries
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = r.cfg.ExportMaxBytes
	}
	return opts
}

func (r *Runtime) listExportDNs(ctx context.Context) ([]string, error) {
	page := r.cfg.InventoryPageSize
	if page <= 0 {
		page = r.pageSize(0)
	}
	_, seconds := r.searchLimits()
	var dns []string
	err := r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		got, e := pageExportDNs(ctx, c, r.cfg.Suffix, uint32(page), seconds)
		if e != nil {
			return e
		}
		dns = got
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(dns, func(i, j int) bool {
		return strings.ToLower(dns[i]) < strings.ToLower(dns[j])
	})
	return uniqueCI(dns), nil
}

func (r *Runtime) readExportEntry(ctx context.Context, dn string) (directory.SearchEntry, error) {
	_, seconds := r.searchLimits()
	var out directory.SearchEntry
	err := r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		ent, e := searchBaseConn(ctx, c, dn, []string{"*", "+"}, 0, seconds)
		if e != nil {
			return e
		}
		out = ldapEntryToExport(ent)
		return nil
	})
	return out, err
}

func pageExportDNs(ctx context.Context, c *ldapclient.Conn, base string, page uint32, seconds int) ([]string, error) {
	if strings.TrimSpace(base) == "" {
		return nil, nil
	}
	req := &ldap.SearchRequest{
		BaseDN:       base,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    0,
		TimeLimit:    seconds,
		Filter:       "(objectClass=*)",
		Attributes:   []string{"1.1"},
	}
	var dns []string
	var cookie []byte
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		res, next, err := c.SearchPage(ctx, req, page, cookie)
		if err != nil {
			if fieldOf(err) == directory.FieldNotFound {
				return nil, nil
			}
			return nil, err
		}
		for _, e := range res.Entries {
			if e == nil || strings.TrimSpace(e.DN) == "" {
				continue
			}
			dns = append(dns, e.DN)
		}
		if len(next) == 0 {
			break
		}
		cookie = next
	}
	return dns, nil
}

func ldapEntryToExport(e *ldap.Entry) directory.SearchEntry {
	if e == nil {
		return directory.SearchEntry{}
	}
	out := directory.SearchEntry{DN: e.DN}
	for _, a := range e.Attributes {
		if a == nil || strings.TrimSpace(a.Name) == "" {
			continue
		}
		vals := a.ByteValues
		if len(vals) == 0 {
			for _, v := range a.Values {
				out.Attributes = append(out.Attributes, directory.AttrKV{Name: a.Name, Value: v})
			}
			continue
		}
		for _, v := range vals {
			out.Attributes = append(out.Attributes, directory.AttrKV{Name: a.Name, Value: string(v)})
		}
	}
	return out
}

func uniqueCI(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		key := strings.ToLower(strings.TrimSpace(s))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if parsed, err := config.ParseDN(s); err == nil {
			s = parsed.String()
		}
		out = append(out, s)
	}
	return out
}
