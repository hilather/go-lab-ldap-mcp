package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver"
)

// The applied engine plan is published as a real store entry at cn=config
// (parity contract Delta D2: cn=config may be a stub). Bootstrap's native
// reconcilers (T-144, internal/directory/native) read these attributes back
// over LDAP as Directory Manager with Compare requests and fail closed when
// the running daemon's applied plan differs from the compiled scenario.
//
// The attribute names and value formats below ARE the read-back contract;
// internal/directory/native mirrors them (it cannot import this main
// package). Any change here must land together with native. Values are
// plain ASCII: integers in base 10, durations as whole seconds, booleans
// as "on"/"off" (389 style), the storage scheme in ldapserver-canonical
// form (uppercase, dashes; empty normalizes to PBKDF2-SHA256).
const (
	configEntryDN = "cn=config"
	engineName    = "native"

	attrEngine             = "labldapEngine"
	attrEngineSuffix       = "labldapEngineSuffix"
	attrPasswordScheme     = "labldapPasswordStorageScheme"
	attrPasswordMinLength  = "labldapPasswordMinLength"
	attrPasswordHistory    = "labldapPasswordHistoryCount"
	attrPasswordMaxAge     = "labldapPasswordMaxAgeSeconds"
	attrLockoutEnabled     = "labldapPasswordLockoutEnabled"
	attrLockoutMaxFailures = "labldapPasswordLockoutMaxFailures"
	attrLockoutDuration    = "labldapPasswordLockoutDurationSeconds"
	attrPlugins            = "labldapPlugins"
)

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func strAttr(name string, values ...string) ldapserver.Attribute {
	a := ldapserver.Attribute{Name: name}
	for _, v := range values {
		a.Values = append(a.Values, []byte(v))
	}
	return a
}

// engineStateEntry renders the compiled engine plan as the cn=config stub
// entry. Only engine-plane facts are published; no credentials, hashes, or
// user data ever appear here.
func engineStateEntry(c *config.Compiled) *ldapserver.Entry {
	p := c.Engine.PasswordPolicy
	scheme := canonicalScheme(p.StorageScheme)
	return &ldapserver.Entry{
		DN: configEntryDN,
		Attributes: []ldapserver.Attribute{
			strAttr("objectClass", "top", "extensibleObject"),
			strAttr("cn", "config"),
			strAttr(attrEngine, engineName),
			strAttr(attrEngineSuffix, c.Engine.Suffix),
			strAttr(attrPasswordScheme, scheme),
			strAttr(attrPasswordMinLength, strconv.Itoa(p.MinLength)),
			strAttr(attrPasswordHistory, strconv.Itoa(p.HistoryCount)),
			strAttr(attrPasswordMaxAge, strconv.FormatInt(int64(p.MaxAge.Seconds()), 10)),
			strAttr(attrLockoutEnabled, onOff(p.LockoutEnabled)),
			strAttr(attrLockoutMaxFailures, strconv.Itoa(p.MaxFailures)),
			strAttr(attrLockoutDuration, strconv.FormatInt(int64(p.LockoutDuration.Seconds()), 10)),
			strAttr(attrPlugins, c.Engine.Plugins...),
		},
	}
}

// canonicalScheme normalizes a storage-scheme spelling exactly as
// ldapserver's NewStandardHasher does; the config compiler already
// rejected unknown schemes, so the fallback is unreachable but safe.
func canonicalScheme(scheme string) string {
	h, err := ldapserver.NewStandardHasher(scheme)
	if err != nil {
		return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(scheme), "_", "-"))
	}
	return h.Scheme
}

// publishEngineState upserts the cn=config entry directly through the
// store. It deliberately bypasses LDAP dispatch: the entry describes the
// engine plane, writes to cn=config over LDAP are refused (outside the
// managed suffix), and the ACI compiler rejects ACLs granting it — only
// the Directory Manager read-back path can see it.
func publishEngineState(ctx context.Context, st ldapserver.Store, e *ldapserver.Entry) error {
	dn, err := config.ParseDN(e.DN)
	if err != nil {
		return fmt.Errorf("labldapd: engine state DN: %w", err)
	}
	return st.Update(ctx, func(tx ldapserver.UpdateTx) error {
		if _, err := tx.Entry(ctx, dn); err == nil {
			return tx.Replace(ctx, e)
		} else if errors.Is(err, ldapserver.ErrNoSuchObject) {
			return tx.Add(ctx, e)
		} else {
			return err
		}
	})
}
