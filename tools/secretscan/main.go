package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// High-confidence credential patterns. Matches are reported by path/line/rule only.
var rules = []struct {
	id string
	re *regexp.Regexp
}{
	{id: "pem-private-key", re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)},
	{id: "github-token", re: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`)},
	{id: "aws-access-key", re: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{id: "slack-token", re: regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`)},
}

var skipDir = map[string]bool{
	".git":         true,
	"node_modules": true,
	"dist":         true,
	"testdata":     true,
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	findings, err := scan(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "secretscan: %v\n", err)
		os.Exit(2)
	}
	if len(findings) == 0 {
		fmt.Println("secretscan: ok")
		return
	}
	for _, f := range findings {
		fmt.Fprintf(os.Stderr, "secretscan: %s:%d rule=%s\n", f.path, f.line, f.rule)
	}
	os.Exit(1)
}

type finding struct {
	path string
	line int
	rule string
}

func scan(root string) ([]finding, error) {
	var out []finding
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		name := d.Name()
		if strings.HasSuffix(name, ".png") || strings.HasSuffix(name, ".jpg") || strings.HasSuffix(name, ".woff") || strings.HasSuffix(name, ".woff2") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			for _, rule := range rules {
				if rule.re.MatchString(line) {
					rel := path
					if r, err := filepath.Rel(root, path); err == nil {
						rel = r
					}
					out = append(out, finding{path: rel, line: i + 1, rule: rule.id})
				}
			}
		}
		return nil
	})
	return out, err
}
