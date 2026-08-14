package reset

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// RecoveryInstructions is the operator-facing Failed-state guidance (T-080).
// It must not mention secrets, DNs of credentials, or Directory Manager.
const RecoveryInstructions = "soft reset did not restore the compiled baseline; " +
	"run labldap-bootstrap apply with lifecycle.startupMode reset, then restart control"

// ObjectSnap is a secret-free configured-object fingerprint.
type ObjectSnap struct {
	DN      string   `json:"dn"`
	Kind    string   `json:"kind"`
	Members []string `json:"members,omitempty"`
}

// Checksum is a lowercase hex SHA-256 of sorted configured objects.
func Checksum(objects []ObjectSnap) string {
	norm := make([]ObjectSnap, 0, len(objects))
	for _, o := range objects {
		dn := canonicalDN(o.DN)
		if dn == "" {
			continue
		}
		members := make([]string, 0, len(o.Members))
		for _, m := range o.Members {
			if m = canonicalDN(m); m != "" {
				members = append(members, m)
			}
		}
		sort.Slice(members, func(i, j int) bool {
			return strings.ToLower(members[i]) < strings.ToLower(members[j])
		})
		kind := strings.ToLower(strings.TrimSpace(o.Kind))
		norm = append(norm, ObjectSnap{DN: dn, Kind: kind, Members: members})
	}
	sort.Slice(norm, func(i, j int) bool {
		if norm[i].Kind != norm[j].Kind {
			return norm[i].Kind < norm[j].Kind
		}
		return strings.ToLower(norm[i].DN) < strings.ToLower(norm[j].DN)
	})
	b, err := json.Marshal(norm)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Verdict is the T-079 comparison. Soft reset never writes the marker.
type Verdict struct {
	OK                bool
	ExpectedRevision  string
	AppliedRevision   string
	InventoryChecksum string
	WantChecksum      string
	Reason            string
}

// Compare reports expected vs applied Directory revision equality using the
// unchanged marker serialNumber and the live inventory checksum.
func Compare(expectedRev, markerSerial, liveChecksum, wantChecksum string, extras int, missing int) Verdict {
	v := Verdict{
		ExpectedRevision:  strings.TrimSpace(expectedRev),
		AppliedRevision:   strings.TrimSpace(markerSerial),
		InventoryChecksum: strings.TrimSpace(liveChecksum),
		WantChecksum:      strings.TrimSpace(wantChecksum),
	}
	switch {
	case v.ExpectedRevision == "":
		v.Reason = "expected directory revision is empty"
	case v.AppliedRevision == "":
		v.Reason = "bootstrap marker serialNumber is missing"
	case v.ExpectedRevision != v.AppliedRevision:
		v.Reason = "compiled directory revision does not match marker serialNumber"
	case extras > 0:
		v.Reason = "runtime-only entries remain under managed containers"
	case missing > 0:
		v.Reason = "compiled baseline objects are missing"
	case v.WantChecksum == "" || v.InventoryChecksum == "":
		v.Reason = "inventory checksum is unavailable"
	case v.InventoryChecksum != v.WantChecksum:
		v.Reason = "live inventory checksum does not match compiled baseline"
	default:
		v.OK = true
	}
	return v
}
