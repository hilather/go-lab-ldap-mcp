package config

import (
	"context"
	"sort"

	"github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1"
)

// Compiled is the offline compiler result used by CLI and later bootstrap.
type Compiled struct {
	Source     string
	Public     *v1alpha1.File
	Normalized *Normalized
	Engine     EnginePlan
	Data       DataPlan
	Revisions  Revisions
	Warning    string
}

type Revisions struct {
	Directory string
	Control   string
	Contract  string
}

// Compile runs parse → default → validate → normalize → plan → hash.
func Compile(ctx context.Context, src []byte, origin string, opt LoadOptions) (*Compiled, error) {
	parsed, err := Load(ctx, src, origin, opt)
	if err != nil {
		return nil, err
	}
	n, err := normalizeAll(ctx, parsed, opt)
	if err != nil {
		return nil, err
	}
	acis, err := compileACIs(n)
	if err != nil {
		return nil, err
	}
	eng := buildEnginePlan(n)
	data := buildDataPlan(n, acis)
	revs, err := hashRevisions(n, data)
	if err != nil {
		return nil, err
	}
	return &Compiled{
		Source:     origin,
		Public:     parsed.Public,
		Normalized: n,
		Engine:     eng,
		Data:       data,
		Revisions:  revs,
		Warning:    warnPersistentReset(parsed.Public),
	}, nil
}

func normalizeAll(ctx context.Context, p *Parsed, opt LoadOptions) (*Normalized, error) {
	f := p.Public
	suffix, err := ParseDN(f.Spec.Directory.Suffix)
	if err != nil {
		return nil, err
	}
	peopleDN, err := ParseDN(f.Spec.Directory.PeopleRDN + "," + f.Spec.Directory.Suffix)
	if err != nil {
		return nil, fieldErr("spec.directory.peopleRDN", "invalid_dn", "peopleRDN is invalid")
	}
	groupsDN, err := ParseDN(f.Spec.Directory.GroupsRDN + "," + f.Spec.Directory.Suffix)
	if err != nil {
		return nil, fieldErr("spec.directory.groupsRDN", "invalid_dn", "groupsRDN is invalid")
	}
	soft := f.Spec.Lifecycle.SoftReset == nil || *f.Spec.Lifecycle.SoftReset
	needUsers := requireUserSeeds(f, opt.Caller)
	resolver := opt.Secrets
	users, err := normalizeUsers(ctx, p.Input, peopleDN, resolver, needUsers)
	if err != nil {
		return nil, err
	}
	groups, err := normalizeGroups(p.Input, users, groupsDN, f.Spec.Directory.NestedGroups)
	if err != nil {
		return nil, err
	}
	policy, err := normalizePolicy(f.Spec.PasswordPolicy)
	if err != nil {
		return nil, err
	}
	tokens, err := normalizeTokens(ctx, p.Input, resolver)
	if err != nil {
		return nil, err
	}
	rtID := f.Spec.RuntimeAccount.ID
	if rtID == "" {
		rtID = "labldap-runtime"
	}
	rtRDN, err := BuildRDN("uid", rtID)
	if err != nil {
		return nil, err
	}
	additional, err := normalizeAdditionalSuffixes(f.Spec.Directory.AdditionalSuffixes, suffix)
	if err != nil {
		return nil, err
	}
	n := &Normalized{
		Engine:             f.Spec.Directory.Engine,
		Suffix:             suffix,
		AdditionalSuffixes: additional,
		PeopleDN:           peopleDN,
		GroupsDN:           groupsDN,
		NestedGroups:       f.Spec.Directory.NestedGroups,
		AllowRawACI:        f.Spec.Directory.AllowRawACI,
		SoftReset:          soft,
		StorageMode:        f.Spec.Lifecycle.StorageMode,
		StartupMode:        f.Spec.Lifecycle.StartupMode,
		Name:               f.Metadata.Name,
		Runtime: NormalizedRuntime{
			ID: rtID,
			DN: rtRDN + "," + peopleDN.String(),
		},
		Users:        users,
		Groups:       groups,
		Policy:       policy,
		Tokens:       tokens,
		OperatorACLs: append([]v1alpha1.ACL(nil), f.Spec.ACLs...),
	}
	if resolver != nil && f.Spec.RuntimeAccount.PasswordFile != "" {
		sec, rerr := resolver.Resolve(ctx, "spec.runtimeAccount.passwordFile", f.Spec.RuntimeAccount.PasswordFile)
		if rerr != nil {
			return nil, rerr
		}
		n.Runtime.Password = sec
	}
	n.freeze()
	return n, nil
}

func normalizeAdditionalSuffixes(raw []string, primary DN) ([]DN, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]DN, 0, len(raw))
	for _, s := range raw {
		d, err := ParseDN(s)
		if err != nil {
			return nil, fieldErr("spec.directory.additionalSuffixes", "invalid_dn", "additional suffix is not a valid DN")
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].FoldedKey() < out[j].FoldedKey()
	})
	_ = primary
	return out, nil
}
