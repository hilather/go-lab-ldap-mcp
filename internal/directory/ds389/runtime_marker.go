package ds389

import (
	"context"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
)

var _ directory.MarkerReader = (*Runtime)(nil)

// ReadMarker is control-plane READ only (KD-R18). Soft reset must not write it.
func (r *Runtime) ReadMarker(ctx context.Context) (directory.BaselineMarker, error) {
	dn := r.cfg.MarkerDN
	if dn == "" && r.cfg.Suffix != "" {
		dn = "cn=" + markerCN + "," + r.cfg.Suffix
	}
	if dn == "" {
		return directory.BaselineMarker{}, directory.Error("marker", directory.FieldConstraint, "marker DN is not configured")
	}
	size, seconds := r.searchLimits()
	var out directory.BaselineMarker
	err := r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		ent, e := searchBaseConn(ctx, c, dn, []string{
			"cn", "objectClass", "serialNumber", "owner", "description", "destinationIndicator",
		}, size, seconds)
		if e != nil {
			if fieldOf(e) == directory.FieldNotFound {
				out = directory.BaselineMarker{DN: dn}
				return nil
			}
			return e
		}
		out = baselineFromEntry(ent)
		return nil
	})
	return out, err
}

func baselineFromEntry(e *ldap.Entry) directory.BaselineMarker {
	if e == nil {
		return directory.BaselineMarker{}
	}
	m := directory.BaselineMarker{DN: e.DN}
	serial := strings.TrimSpace(e.GetAttributeValue("serialNumber"))
	dest := strings.TrimSpace(e.GetAttributeValue("destinationIndicator"))
	owner := strings.TrimSpace(e.GetAttributeValue("owner"))
	desc := strings.TrimSpace(e.GetAttributeValue("description"))
	if serial != "" || dest != "" {
		m.AppliedRevision = serial
		m.ExpectedRevision = dest
		m.ApplyVersion = owner
		m.AppliedAt = desc
		return m
	}
	if parsed, ok := parseMarkerJSON(desc); ok {
		m.AppliedRevision = parsed.SerialNumber
		m.ExpectedRevision = parsed.DestinationIndicator
		m.ApplyVersion = parsed.Owner
		m.AppliedAt = parsed.AppliedAt
		return m
	}
	m.AppliedAt = desc
	m.ApplyVersion = owner
	return m
}
