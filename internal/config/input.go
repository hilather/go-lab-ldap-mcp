package config

import "github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1"

// Input is the internal working model after convert and before normalize.
// Secret fields are path references only at this layer.
type Input struct {
	Public         v1alpha1.File
	RuntimeAccount RuntimeAccountInput
	Users          []UserInput
	Groups         []GroupInput
	Tokens         []TokenInput
}

type SecretRef struct {
	File string
}

type RuntimeAccountInput struct {
	ID       string
	Password SecretRef
}

type UserInput struct {
	ID         string
	UID        string
	RDN        string
	DN         string
	Password   SecretRef
	Enabled    *bool
	Attributes map[string]string
}

type GroupInput struct {
	ID      string
	Members []v1alpha1.Member
}

type TokenInput struct {
	ID     string
	Secret SecretRef
	Scopes []string
}
