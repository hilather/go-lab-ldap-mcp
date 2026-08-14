package directory

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
