package dirsrv

import (
	"regexp"
	"strings"
)

var (
	pemPrivate = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	// dscontainer first-boot: IMPORTANT: Set cn=Directory Manager password to "<pw>"
	// plus common variants and DS_DM_PASSWORD= env echoes.
	passwordAssign = regexp.MustCompile(`(?i)((?:set )?cn=Directory Manager password to |password set to |Root DN password: |DS_DM_PASSWORD=)("?)([^"\s]+)("?)`)
)

func redactLogs(s string, secrets ...string) string {
	s = pemPrivate.ReplaceAllString(s, "[redacted-pem]")
	s = passwordAssign.ReplaceAllString(s, "${1}${2}[redacted]${4}")
	for _, sec := range secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "[redacted]")
		}
	}
	return s
}
