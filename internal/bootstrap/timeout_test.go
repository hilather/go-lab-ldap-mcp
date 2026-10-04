package bootstrap

import (
	"testing"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1"
)

func TestConfiguredLDAPTimeoutPropagatesAcrossBootstrapPhases(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want time.Duration
	}{{"17s", 17 * time.Second}, {"", 5 * time.Second}, {"invalid", 5 * time.Second}, {"0s", 5 * time.Second}} {
		t.Run(tc.raw, func(t *testing.T) {
			c := &config.Compiled{Public: &v1alpha1.File{}, Normalized: &config.Normalized{}}
			c.Public.Spec.Limits.LDAPDialTimeout = tc.raw
			opt := Options{Now: time.Now}
			got := map[string]time.Duration{
				"wait":         waitRequestFrom(c, opt, "").DialTimeout,
				"tls":          tlsRequestFrom(c, opt, "", true).DialTimeout,
				"tree":         treeRequestFrom(c, opt, "", true).DialTimeout,
				"seed":         seedRequestFrom(c, opt, "", true).DialTimeout,
				"capabilities": capabilityRequestFrom(c, opt, "", true).DialTimeout,
				"drift":        driftRequestFrom(c, opt, "", true).DialTimeout,
				"marker":       markerRequestFrom(c, opt, "", true).DialTimeout,
				"verify":       verifyRequestFrom(c, opt, "", true).DialTimeout,
			}
			for phase, timeout := range got {
				if timeout != tc.want {
					t.Errorf("%s timeout=%s want%s", phase, timeout, tc.want)
				}
			}
		})
	}
}
