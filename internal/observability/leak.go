package observability

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// CanarySecret is the planted value in testdata/canary-leak.txt. Tests that
// scan a clean log must fail if this string appears.
const CanarySecret = "lab-canary-must-fail-scan-32chars!"

// Finding is a leak-scanner hit. The matching secret is never copied into
// the finding so reports stay safe to log.
type Finding struct {
	Line int
	Rule string
}

var leakRules = []struct {
	id string
	re *regexp.Regexp
}{
	{id: "authorization-bearer", re: regexp.MustCompile(`(?i)authorization:\s*bearer\s+\S+`)},
	{id: "cookie-header", re: regexp.MustCompile(`(?i)(?:^|[\s;])cookie:\s*\S+`)},
	{id: "set-cookie-header", re: regexp.MustCompile(`(?i)set-cookie:\s*\S+`)},
	{id: "canary-secret", re: regexp.MustCompile(regexp.QuoteMeta(CanarySecret))},
}

// ScanReader looks for header leaks, the canary secret, and any extra
// caller-supplied secrets (token values, seed passwords, session IDs).
func ScanReader(r io.Reader, secrets ...string) ([]Finding, error) {
	if r == nil {
		return nil, nil
	}
	var extra []*regexp.Regexp
	for _, s := range secrets {
		s = strings.TrimSpace(s)
		if s == "" || s == "[redacted]" {
			continue
		}
		extra = append(extra, regexp.MustCompile(regexp.QuoteMeta(s)))
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var out []Finding
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		for _, rule := range leakRules {
			if rule.re.MatchString(text) {
				out = append(out, Finding{Line: line, Rule: rule.id})
			}
		}
		for i, re := range extra {
			if re.MatchString(text) {
				out = append(out, Finding{Line: line, Rule: "secret:" + extraRuleName(i)})
			}
		}
	}
	return out, sc.Err()
}

func extraRuleName(i int) string {
	return fmt.Sprintf("%d", i)
}

// ScanFile scans a complete log file.
func ScanFile(path string, secrets ...string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ScanReader(f, secrets...)
}

// ReportFindings formats hits without echoing secret values.
func ReportFindings(findings []Finding) string {
	if len(findings) == 0 {
		return ""
	}
	var b strings.Builder
	for _, f := range findings {
		fmt.Fprintf(&b, "line %d rule=%s\n", f.Line, f.Rule)
	}
	return b.String()
}
