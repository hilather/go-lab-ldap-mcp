package config

import (
	"context"

	"github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1"
)

type LoadCaller int

const (
	CallerUnspecified LoadCaller = iota
	CallerBootstrap
	CallerControl
	CallerCLI
)

type LoadOptions struct {
	Secrets SecretResolver
	Caller  LoadCaller
}

// Parsed is the T-009/T-011 result. Later tasks add Normalized, plans, and hashes.
type Parsed struct {
	Source string
	Public *v1alpha1.File
	Input  *Input
}

// Load parses and converts a scenario document. It must not dial LDAP.
// Defaulting, semantic validation, and compilation land in later M1 tasks.
func Load(ctx context.Context, src []byte, origin string, opt LoadOptions) (*Parsed, error) {
	_ = ctx
	_ = opt
	pub, err := Parse(src, origin)
	if err != nil {
		return nil, err
	}
	applyDefaults(pub)
	if err := validateSettings(pub); err != nil {
		return nil, err
	}
	in, err := DefaultConverter().Convert(pub)
	if err != nil {
		return nil, err
	}
	return &Parsed{Source: origin, Public: pub, Input: in}, nil
}

// Validate is the T-010 library helper: parse + convert, no CLI.
func Validate(src []byte, origin string) error {
	_, err := Load(context.Background(), src, origin, LoadOptions{Caller: CallerCLI})
	return err
}
