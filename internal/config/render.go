package config

import (
	"bytes"
	"encoding/json"
	"sort"
)

// RedactedPlan is the stable JSON document emitted by `labldap plan`.
type RedactedPlan struct {
	Revisions Revisions  `json:"revisions"`
	Engine    EnginePlan `json:"engine"`
	Data      DataPlan   `json:"data"`
	Warning   string     `json:"warning,omitempty"`
}

func (c *Compiled) RedactedPlan() RedactedPlan {
	return RedactedPlan{
		Revisions: c.Revisions,
		Engine:    c.Engine,
		Data:      c.Data,
		Warning:   c.Warning,
	}
}

func (c *Compiled) RedactedJSON() ([]byte, error) {
	b, err := json.Marshal(c.RedactedPlan())
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, b, "", "  "); err != nil {
		return nil, err
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

func (c *Compiled) NormalizeJSON() ([]byte, error) {
	type nu struct {
		ID, UID, DN string
		Enabled     bool
		Classes     []string
		Attrs       []AttrKV
	}
	users := make([]nu, 0, len(c.Normalized.Users))
	for _, u := range c.Normalized.Users {
		users = append(users, nu{u.ID, u.UID, u.DN, u.Enabled, u.ObjectClasses, u.Attributes})
	}
	type ng struct {
		ID      string
		DN      string
		Members []MemberRef
	}
	groups := make([]ng, 0, len(c.Normalized.Groups))
	for _, g := range c.Normalized.Groups {
		groups = append(groups, ng{g.ID, g.DN, g.Members})
	}
	type nt struct {
		ID     string
		Scopes []string
		Digest string
	}
	tokens := make([]nt, 0, len(c.Normalized.Tokens))
	for _, t := range c.Normalized.Tokens {
		scopes := append([]string(nil), t.Scopes...)
		sort.Strings(scopes)
		tokens = append(tokens, nt{t.ID, scopes, t.Secret.Digest})
	}
	doc := map[string]any{
		"name":     c.Normalized.Name,
		"suffix":   c.Normalized.Suffix.String(),
		"users":    users,
		"groups":   groups,
		"tokens":   tokens,
		"policy":   c.Normalized.Policy,
		"contract": CompilerContract,
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, b, "", "  "); err != nil {
		return nil, err
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}
