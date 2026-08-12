package config

import (
	"context"
	"fmt"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
)

func normalizeUsers(ctx context.Context, in *Input, peopleDN DN, resolver SecretResolver, requireSeeds bool) ([]NormalizedUser, error) {
	var acc []*apperr.Error
	seen := map[string]int{}
	out := make([]NormalizedUser, 0, len(in.Users))
	for i, u := range in.Users {
		path := fmt.Sprintf("spec.users[%d]", i)
		if u.ID == "" {
			acc = append(acc, fieldErr(path+".id", "required", "user id is required"))
			continue
		}
		if prev, ok := seen[u.ID]; ok {
			acc = append(acc, fieldErr(path+".id", "duplicate", fmt.Sprintf("duplicate user id (also spec.users[%d])", prev)))
			continue
		}
		seen[u.ID] = i
		uid := u.UID
		if uid == "" {
			uid = u.ID
		}
		rdn, err := BuildRDN("uid", uid)
		if err != nil {
			acc = append(acc, fieldErr(path+".uid", "invalid_rdn", "cannot build uid RDN"))
			continue
		}
		gen := rdn + "," + peopleDN.String()
		if u.RDN != "" {
			want := strings.ToLower(rdn)
			got := strings.ToLower(strings.ReplaceAll(u.RDN, " ", ""))
			if got != want {
				acc = append(acc, fieldErr(path+".rdn", "identity_mismatch", "rdn does not match uid"))
				acc = append(acc, fieldErr(path+".id", "identity_mismatch", "id/uid/rdn are inconsistent"))
			}
		}
		if u.DN != "" {
			want, perr := ParseDN(gen)
			got, gerr := ParseDN(u.DN)
			if perr != nil || gerr != nil || !want.Equal(got) {
				acc = append(acc, fieldErr(path+".dn", "identity_mismatch", "dn does not match generated uid RDN under people container"))
				acc = append(acc, fieldErr(path+".id", "identity_mismatch", "id/uid/dn are inconsistent"))
			}
		}
		var attrs []AttrKV
		for name, val := range u.Attributes {
			if ForbiddenUserAttr(name) {
				acc = append(acc, fieldErr(path+".attributes."+name, "forbidden_attribute", "attribute is not allowed on users"))
				continue
			}
			attrs = append(attrs, AttrKV{Name: CanonicalAttr(name), Value: val})
		}
		enabled := true
		if u.Enabled != nil {
			enabled = *u.Enabled
		}
		nu := NormalizedUser{
			ID:            u.ID,
			UID:           uid,
			DN:            gen,
			Enabled:       enabled,
			ObjectClasses: append([]string(nil), RequiredUserObjectClasses()...),
			Attributes:    attrs,
		}
		if requireSeeds {
			if u.Password.File == "" {
				acc = append(acc, fieldErr(path+".passwordFile", "required", "user passwordFile is required"))
			} else if resolver != nil {
				sec, rerr := resolver.Resolve(ctx, path+".passwordFile", u.Password.File)
				if rerr != nil {
					acc = append(acc, asConfigErr(rerr))
				} else {
					cp := sec
					nu.Password = &cp
				}
			}
		}
		out = append(out, nu)
	}
	if err := joinConfig(acc); err != nil {
		return nil, err
	}
	sortUsers(out)
	return out, nil
}
