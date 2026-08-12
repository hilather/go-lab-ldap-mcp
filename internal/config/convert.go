package config

import (
	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1"
)

// Converter turns a public document into the internal input model.
type Converter interface {
	Convert(f *v1alpha1.File) (*Input, error)
}

type v1alpha1Converter struct{}

func (v1alpha1Converter) Convert(f *v1alpha1.File) (*Input, error) {
	if f == nil {
		return nil, apperr.New(apperr.CodeConfiguration, "missing document").
			WithField(apperr.Field{Path: "document", Code: "required", Message: "document is required"})
	}
	in := &Input{Public: *f}
	in.RuntimeAccount.ID = f.Spec.RuntimeAccount.ID
	in.RuntimeAccount.Password = SecretRef{File: f.Spec.RuntimeAccount.PasswordFile}
	in.Users = make([]UserInput, len(f.Spec.Users))
	for i, u := range f.Spec.Users {
		in.Users[i] = UserInput{
			ID:       u.ID,
			UID:      u.UID,
			RDN:      u.RDN,
			DN:       u.DN,
			Password: SecretRef{File: u.PasswordFile},
			Enabled:  u.Enabled,
		}
		if u.Attributes != nil {
			in.Users[i].Attributes = copyMap(u.Attributes)
		}
	}
	in.Groups = append([]GroupInput(nil), make([]GroupInput, len(f.Spec.Groups))...)
	for i, g := range f.Spec.Groups {
		in.Groups[i] = GroupInput{ID: g.ID, Members: append([]v1alpha1.Member(nil), g.Members...)}
	}
	in.Tokens = make([]TokenInput, len(f.Spec.Tokens))
	for i, t := range f.Spec.Tokens {
		in.Tokens[i] = TokenInput{
			ID:     t.ID,
			Secret: SecretRef{File: t.SecretFile},
			Scopes: append([]string(nil), t.Scopes...),
		}
	}
	return in, nil
}

func copyMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// DefaultConverter is the v1alpha1 conversion implementation.
func DefaultConverter() Converter { return v1alpha1Converter{} }
