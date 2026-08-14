package directory

import "strings"

// ControlAssertionOID is LDAP assertion control (RFC 4528). When present in
// T-044 Controls, ds389 sends it on If-Match updates. When absent, If-Match
// has a residual TOCTOU race; v1 still uses revision checks and a keyed lock
// (KD-R24) and must not fake atomicity.
const ControlAssertionOID = "1.3.6.1.1.12"

// Capabilities is the T-044 measured engine report. Secret-free.
// Bootstrap inspect returns this shape; runtime CapabilityInspector does too.
type Capabilities struct {
	EngineVendor   string   `json:"engineVendor"`
	EngineVersion  string   `json:"engineVersion"`
	AdapterVersion string   `json:"adapterVersion"`
	Transports     []string `json:"transports"`
	Plugins        []string `json:"plugins"`
	PasswordScheme string   `json:"passwordScheme"`
	Controls       []string `json:"controls"`
	RequiredOK     bool     `json:"requiredOK"`
}

// HasControl reports whether oid appears in Controls (case-insensitive).
func (c Capabilities) HasControl(oid string) bool {
	want := strings.TrimSpace(oid)
	for _, got := range c.Controls {
		if strings.EqualFold(strings.TrimSpace(got), want) {
			return true
		}
	}
	return false
}

// HasAssertionControl is true when 1.3.6.1.1.12 was advertised on the Root DSE.
func (c Capabilities) HasAssertionControl() bool {
	return c.HasControl(ControlAssertionOID)
}
