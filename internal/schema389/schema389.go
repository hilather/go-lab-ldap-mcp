// Package schema389 is the attribute-type vocabulary of the pinned 389 DS
// image (deploy/docker/dirsrv.digest). Native ACI parsing and config
// compilation use it to reject targetattr names 389 would reject
// (contract C8, resolved CAND-33). It is data only and imports nothing
// from the engine packages.
package schema389

import (
	_ "embed"
	"strings"
	"sync"
)

//go:embed attributetypes.txt
var attributeTypesFile string

var (
	once  sync.Once
	known map[string]struct{}
	// primary maps every lowercase NAME, alias and OID to the NAME.
	primary map[string]string
	image   string
	count   int
)

func load() {
	known = map[string]struct{}{}
	primary = map[string]string{}
	for _, line := range strings.Split(attributeTypesFile, "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "# image "); ok {
			image = rest
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		count++
		fields := strings.Fields(line)
		for _, f := range fields {
			known[strings.ToLower(f)] = struct{}{}
			if len(fields) > 1 {
				primary[strings.ToLower(f)] = fields[1]
			}
		}
	}
}

// Known reports whether the base of an attribute description (the part
// before the first ';') is a NAME, alias or OID of an attributeType in the
// pinned 389 schema. The comparison is case-insensitive; options are not
// checked, as on 389 (oracle probes 16 and 19).
func Known(desc string) bool {
	once.Do(load)
	base, _, _ := strings.Cut(desc, ";")
	_, ok := known[strings.ToLower(strings.TrimSpace(base))]
	return ok
}

// Primary rewrites the base of an attribute description that is an alias
// or OID in the pinned 389 schema to the attribute type's NAME, keeping any
// options as written (pwdHistory;x-a becomes passwordHistory;x-a). Unknown
// names come back trimmed and unchanged. targetattr names are compared
// literally on both engines, so a name meant to cover the stored attribute
// must use this spelling.
func Primary(desc string) string {
	once.Do(load)
	desc = strings.TrimSpace(desc)
	base, opts, hasOpts := strings.Cut(desc, ";")
	name, ok := primary[strings.ToLower(strings.TrimSpace(base))]
	if !ok {
		return desc
	}
	if hasOpts {
		return name + ";" + opts
	}
	return name
}

// Image returns the image reference recorded in the data file header.
func Image() string { once.Do(load); return image }

// Count returns the number of attributeTypes in the data file.
func Count() int { once.Do(load); return count }
