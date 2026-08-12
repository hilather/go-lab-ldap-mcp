package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

func hashRevisions(n *Normalized, data DataPlan) (Revisions, error) {
	dir := map[string]any{
		"contract":       CompilerContract,
		"suffix":         n.Suffix.String(),
		"users":          directoryUsers(n),
		"groups":         directoryGroups(n),
		"policy":         n.Policy,
		"acis":           data.ACIs,
		"runtimeAccount": n.Runtime.ID,
		"runtimeDigest":  n.Runtime.Password.Digest,
		"softReset":      n.SoftReset,
	}
	if n.SoftReset {
		seeds := map[string]string{}
		for _, u := range n.Users {
			if u.Password != nil {
				seeds[u.ID] = u.Password.Digest
			}
		}
		dir["userSeedDigests"] = seeds
	}
	ctl := map[string]any{
		"contract":     CompilerContract,
		"tokens":       controlTokens(n),
		"listen":       n.Name,
		"startupMode":  n.StartupMode,
		"storageMode":  n.StorageMode,
		"softReset":    n.SoftReset,
		"mcpMutations": false,
	}
	dh, err := canonicalJSONHash(dir)
	if err != nil {
		return Revisions{}, err
	}
	ch, err := canonicalJSONHash(ctl)
	if err != nil {
		return Revisions{}, err
	}
	return Revisions{Directory: dh, Control: ch, Contract: CompilerContract}, nil
}

func directoryUsers(n *Normalized) []map[string]any {
	out := make([]map[string]any, 0, len(n.Users))
	for _, u := range n.Users {
		out = append(out, map[string]any{
			"id": u.ID, "uid": u.UID, "dn": u.DN, "enabled": u.Enabled,
			"attrs": u.Attributes, "oc": u.ObjectClasses,
		})
	}
	return out
}

func directoryGroups(n *Normalized) []map[string]any {
	out := make([]map[string]any, 0, len(n.Groups))
	for _, g := range n.Groups {
		members := make([]string, 0, len(g.Members))
		for _, m := range g.Members {
			members = append(members, m.Kind+":"+m.ID)
		}
		sort.Strings(members)
		out = append(out, map[string]any{"id": g.ID, "dn": g.DN, "members": members})
	}
	return out
}

func controlTokens(n *Normalized) []map[string]any {
	out := make([]map[string]any, 0, len(n.Tokens))
	for _, t := range n.Tokens {
		scopes := append([]string(nil), t.Scopes...)
		sort.Strings(scopes)
		out = append(out, map[string]any{"id": t.ID, "scopes": scopes, "digest": t.Secret.Digest})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i]["id"].(string) < out[j]["id"].(string)
	})
	return out
}

func canonicalJSONHash(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
