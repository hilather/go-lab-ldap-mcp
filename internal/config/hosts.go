package config

import (
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1"
)

// AllowedHostsEnv is the comma-separated extra Host allow-list (ADR-0010).
const AllowedHostsEnv = "LABLDAP_MANAGEMENT_ALLOWED_HOSTS"

func applyAllowedHostSources(f *v1alpha1.File, opt LoadOptions) error {
	envItems := SplitHostList(os.Getenv(AllowedHostsEnv))
	var acc []*apperr.Error
	acc = append(acc, checkAllowedHosts(AllowedHostsEnv, envItems)...)
	acc = append(acc, checkAllowedHosts("--management-allowed-host", opt.ExtraAllowedHosts)...)
	if err := joinConfig(acc); err != nil {
		return err
	}
	f.Spec.Management.AllowedHosts = UnionAllowedHosts(
		f.Spec.Management.AllowedHosts,
		envItems,
		opt.ExtraAllowedHosts,
	)
	return nil
}

// SplitHostList splits a comma-separated host list. Empty input is nil.
func SplitHostList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

// UnionAllowedHosts concatenates host lists, skipping blanks and
// case-insensitive duplicates. Order is first-seen.
func UnionAllowedHosts(lists ...[]string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, list := range lists {
		for _, h := range list {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			key := strings.ToLower(h)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, h)
		}
	}
	return out
}

func checkAllowedHosts(basePath string, hosts []string) []*apperr.Error {
	var acc []*apperr.Error
	for i, h := range hosts {
		path := basePath + "[" + strconv.Itoa(i) + "]"
		if code, msg := validateAllowedHost(h); code != "" {
			acc = append(acc, fieldErr(path, code, msg))
		}
	}
	return acc
}

func validateAllowedHost(raw string) (code, msg string) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "empty", "allowed host must not be empty"
	}
	if s == "*" {
		return "wildcard", "wildcard hosts are not allowed"
	}
	if strings.Contains(s, "://") {
		return "invalid_host", "allowed host must not include a URL scheme"
	}
	if strings.ContainsAny(s, "/?#@ \t\r\n") {
		return "invalid_host", "allowed host must not include a path, query, or userinfo"
	}
	host, port, hasPort, ok := splitAllowedHost(s)
	if !ok {
		return "invalid_host", "allowed host must be a hostname, IP, or host:port"
	}
	if hasPort && !validTCPPort(port) {
		return "invalid_host", "allowed host port must be 1-65535"
	}
	if !validHostNameOrIP(host) {
		return "invalid_host", "allowed host must be a hostname or IP"
	}
	return "", ""
}

func splitAllowedHost(s string) (host, port string, hasPort, ok bool) {
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 1 {
			return "", "", false, false
		}
		host = s[1:end]
		rest := s[end+1:]
		if rest == "" {
			return host, "", false, true
		}
		if !strings.HasPrefix(rest, ":") || rest == ":" {
			return "", "", false, false
		}
		return host, rest[1:], true, true
	}
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p, true, true
	}
	if strings.Count(s, ":") > 0 {
		if net.ParseIP(s) != nil {
			return s, "", false, true
		}
		return "", "", false, false
	}
	return s, "", false, true
}

func validTCPPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535
}

func validHostNameOrIP(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" || strings.Contains(host, "*") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	return validDNSName(host)
}

func validDNSName(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	s = strings.TrimSuffix(s, ".")
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}
