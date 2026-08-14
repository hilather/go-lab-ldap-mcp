package ds389

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
)

const (
	markerCN           = "labldap-baseline"
	markerEncodingAttr = "attributes"
	markerEncodingJSON = "description-json"
)

type markerJSON struct {
	SerialNumber         string `json:"serialNumber"`
	DestinationIndicator string `json:"destinationIndicator"`
	Owner                string `json:"owner"`
	AppliedAt            string `json:"appliedAt"`
}

func (e Engine) ReadMarker(ctx context.Context, req bootstrap.MarkerRequest) (bootstrap.Marker, error) {
	if err := ctx.Err(); err != nil {
		return bootstrap.Marker{}, bootstrap.PhaseError("marker", "apply_failed", "marker read canceled").Wrap(err)
	}
	if req.DialTimeout <= 0 {
		req.DialTimeout = 5 * time.Second
	}
	dn := req.DN
	if dn == "" {
		return bootstrap.Marker{}, bootstrap.PhaseError("marker", "apply_failed", "compiled marker DN is empty")
	}
	dial := e.TreeDial
	if dial == nil {
		dial = defaultTreeDial
	}
	conn, err := dial(ctx, req.TreeRequest)
	if err != nil {
		return bootstrap.Marker{}, bootstrap.PhaseError("marker", "apply_failed", "could not bind as Directory Manager to read the marker").Wrap(err)
	}
	defer conn.Close()
	return readMarkerEntry(conn, dn)
}

func (e Engine) WriteMarker(ctx context.Context, req bootstrap.MarkerRequest) error {
	if err := ctx.Err(); err != nil {
		return bootstrap.PhaseError("marker", "apply_failed", "marker write canceled").Wrap(err)
	}
	if e.FailWriteMarker != nil {
		return e.FailWriteMarker
	}
	if !req.Write {
		return bootstrap.PhaseError("marker", "apply_failed", "marker write is apply-only")
	}
	if req.DialTimeout <= 0 {
		req.DialTimeout = 5 * time.Second
	}
	dn := req.DN
	if dn == "" {
		return bootstrap.PhaseError("marker", "apply_failed", "compiled marker DN is empty")
	}
	if looksSecret(req.AppliedRevision) || looksSecret(req.ExpectedRevision) || looksSecret(req.ApplyVersion) {
		return bootstrap.PhaseError("marker", "apply_failed", "marker must not contain secret material")
	}
	dial := e.TreeDial
	if dial == nil {
		dial = defaultTreeDial
	}
	conn, err := dial(ctx, req.TreeRequest)
	if err != nil {
		return bootstrap.PhaseError("marker", "apply_failed", "could not bind as Directory Manager to write the marker").Wrap(err)
	}
	defer conn.Close()

	exists, err := entryExists(conn, dn)
	if err != nil {
		return bootstrap.PhaseError("marker", "apply_failed", "could not read the baseline marker").Wrap(err)
	}
	if err := writeMarkerPreferred(conn, dn, req, exists); err != nil {
		if !isSchemaReject(err) {
			return bootstrap.PhaseError("marker", "apply_failed", "could not write the baseline marker").Wrap(err)
		}
		if err := writeMarkerJSON(conn, dn, req, exists); err != nil {
			return bootstrap.PhaseError("marker", "apply_failed", "could not write the baseline marker").Wrap(err)
		}
	}
	return nil
}

func writeMarkerPreferred(conn treeConn, dn string, req bootstrap.MarkerRequest, exists bool) error {
	if !exists {
		add := ldap.NewAddRequest(dn, nil)
		add.Attribute("objectClass", []string{"top", "device"})
		add.Attribute("cn", []string{markerCN})
		add.Attribute("serialNumber", []string{req.AppliedRevision})
		add.Attribute("owner", []string{req.ApplyVersion})
		add.Attribute("description", []string{req.AppliedAt})
		add.Attribute("destinationIndicator", []string{req.ExpectedRevision})
		return conn.Add(add)
	}
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace("serialNumber", []string{req.AppliedRevision})
	mod.Replace("owner", []string{req.ApplyVersion})
	mod.Replace("description", []string{req.AppliedAt})
	mod.Replace("destinationIndicator", []string{req.ExpectedRevision})
	return conn.Modify(mod)
}

func writeMarkerJSON(conn treeConn, dn string, req bootstrap.MarkerRequest, exists bool) error {
	payload, err := json.Marshal(markerJSON{
		SerialNumber:         req.AppliedRevision,
		DestinationIndicator: req.ExpectedRevision,
		Owner:                req.ApplyVersion,
		AppliedAt:            req.AppliedAt,
	})
	if err != nil {
		return err
	}
	if !exists {
		add := ldap.NewAddRequest(dn, nil)
		add.Attribute("objectClass", []string{"top", "device"})
		add.Attribute("cn", []string{markerCN})
		add.Attribute("description", []string{string(payload)})
		return conn.Add(add)
	}
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace("description", []string{string(payload)})
	return conn.Modify(mod)
}

func readMarkerEntry(conn treeConn, dn string) (bootstrap.Marker, error) {
	entry, err := readEntry(conn, dn, []string{
		"cn", "objectClass", "serialNumber", "owner", "description", "destinationIndicator",
	})
	if err != nil {
		if isNoSuchObject(err) {
			return bootstrap.Marker{DN: dn}, nil
		}
		return bootstrap.Marker{}, bootstrap.PhaseError("marker", "apply_failed", "could not read the baseline marker").Wrap(err)
	}
	m := bootstrap.Marker{DN: dn}
	serial := firstAttr(entry, "serialNumber")
	dest := firstAttr(entry, "destinationIndicator")
	owner := firstAttr(entry, "owner")
	desc := firstAttr(entry, "description")
	if serial != "" || dest != "" {
		m.AppliedRevision = serial
		m.ExpectedRevision = dest
		m.ApplyVersion = owner
		m.AppliedAt = desc
		m.Encoding = markerEncodingAttr
		return m, nil
	}
	if parsed, ok := parseMarkerJSON(desc); ok {
		m.AppliedRevision = parsed.SerialNumber
		m.ExpectedRevision = parsed.DestinationIndicator
		m.ApplyVersion = parsed.Owner
		m.AppliedAt = parsed.AppliedAt
		m.Encoding = markerEncodingJSON
		return m, nil
	}
	m.AppliedAt = desc
	m.ApplyVersion = owner
	return m, nil
}

func parseMarkerJSON(s string) (markerJSON, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s[0] != '{' {
		return markerJSON{}, false
	}
	var doc markerJSON
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		return markerJSON{}, false
	}
	return doc, true
}

func firstAttr(e *ldap.Entry, name string) string {
	if e == nil {
		return ""
	}
	return strings.TrimSpace(e.GetAttributeValue(name))
}

func isSchemaReject(err error) bool {
	var le *ldap.Error
	if !errors.As(err, &le) {
		return false
	}
	switch le.ResultCode {
	case ldap.LDAPResultObjectClassViolation,
		ldap.LDAPResultUndefinedAttributeType,
		ldap.LDAPResultInvalidAttributeSyntax,
		ldap.LDAPResultConstraintViolation,
		ldap.LDAPResultObjectClassModsProhibited:
		return true
	default:
		return false
	}
}

func looksSecret(s string) bool {
	low := strings.ToLower(s)
	if strings.Contains(low, "password") || strings.Contains(low, "secret") || strings.Contains(low, "token") {
		return true
	}
	return strings.Contains(s, "\n") && strings.Contains(low, "begin ")
}
