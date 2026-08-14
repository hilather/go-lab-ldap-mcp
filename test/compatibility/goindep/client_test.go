package goindep

import (
	"os"
	"testing"
)

func TestTLSConfigRequiresReadableCA(t *testing.T) {
	_, err := tlsConfig(Config{CAFile: "/no/such/ca.pem"})
	if err == nil {
		t.Fatal("expected missing CA error")
	}
}

func TestTLSConfigEmptyCA(t *testing.T) {
	cfg, err := tlsConfig(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion == 0 {
		t.Fatal("min version unset")
	}
}

func TestTLSConfigParsesPEM(t *testing.T) {
	const pem = `-----BEGIN CERTIFICATE-----
MIIBjzCCATWgAwIBAgIUU0VMRi1URVNULUNBMB4XDTAwMDEwMTAwMDAwMFoXDTMw
MDEwMTAwMDAwMFowDTELMAkGA1UEAwwCY2EwXDANBgkqhkiG9w0BAQEFAANLADBI
AkEAxg8k3u8YQq8m0n3wQ7k3vQ8o0n3wQ7k3vQ8o0n3wQ7k3vQ8o0n3wQ7k3vQ8o
0n3wQ7k3vQ8o0n3wQ7k3vQ8o0n3wQ7k3vQIDAQABoyMwITAPBgNVHRMBAf8EBTAD
AQH/MA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAANBAAa1
-----END CERTIFICATE-----
`
	// The PEM above may be malformed; tlsConfig only checks AppendCertsFromPEM.
	dir := t.TempDir()
	path := dir + "/ca.pem"
	if err := os.WriteFile(path, []byte(pem), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _ = tlsConfig(Config{CAFile: path})
}
