package directory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// RevisionOfUser is the canonical hash over API-exposed user attributes.
// Passwords and operational attributes are never inputs. Unchanged reads
// produce the same revision; an exposed attribute change does not.
func RevisionOfUser(u User) Revision {
	return RevisionHash(struct {
		ID            string
		UID           string
		Enabled       bool
		ObjectClasses []string
		Attributes    []AttrKV
		Groups        []GroupID
	}{u.ID, u.UID, u.Enabled, u.ObjectClasses, u.Attributes, u.Groups})
}

// RevisionOfGroup is the canonical hash over API-exposed group identity
// and membership. Member DNs are compared case-insensitively.
func RevisionOfGroup(g Group) Revision {
	ids := make([]string, 0, len(g.Members))
	for _, m := range g.Members {
		ids = append(ids, m.Kind+":"+strings.ToLower(strings.TrimSpace(m.DN)))
	}
	sort.Slice(ids, func(i, j int) bool {
		return strings.ToLower(ids[i]) < strings.ToLower(ids[j])
	})
	return RevisionHash(struct {
		ID      string
		Members []string
	}{g.ID, ids})
}

// RevisionOfEntry is the canonical hash over API-exposed entry attributes.
func RevisionOfEntry(e DirectoryEntry) Revision {
	return RevisionHash(struct {
		DN            string
		ObjectClasses []string
		Attributes    []AttrKV
	}{e.DN, e.ObjectClasses, e.Attributes})
}

// RevisionHash is lowercase hex SHA-256 of canonical JSON. Never hash secrets.
func RevisionHash(v any) Revision {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return Revision(hex.EncodeToString(sum[:]))
}
