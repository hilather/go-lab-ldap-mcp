package config

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1"
	"gopkg.in/yaml.v3"
)

// Parse decodes a single YAML document into public v1alpha1 types.
// It does not resolve secrets or connect to LDAP.
func Parse(src []byte, origin string) (*v1alpha1.File, error) {
	if len(bytes.TrimSpace(src)) == 0 {
		return nil, apperr.New(apperr.CodeConfiguration, "configuration is empty").
			WithField(apperr.Field{Path: originOrDoc(origin), Code: "empty", Message: "file is empty"})
	}

	var acc []*apperr.Error
	var root yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(src))
	if err := dec.Decode(&root); err != nil {
		return nil, apperr.New(apperr.CodeConfiguration, "invalid YAML").
			WithField(apperr.Field{Path: originOrDoc(origin), Code: "parse", Message: safeYAMLMessage(err)})
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF && err != nil {
		acc = append(acc, apperr.New(apperr.CodeConfiguration, "invalid YAML").
			WithField(apperr.Field{Path: originOrDoc(origin), Code: "trailing_document", Message: "trailing YAML document is not allowed"}))
	} else if err == nil && extra.Kind != 0 {
		acc = append(acc, apperr.New(apperr.CodeConfiguration, "invalid YAML").
			WithField(apperr.Field{Path: originOrDoc(origin), Code: "trailing_document", Message: "trailing YAML document is not allowed"}))
	}

	acc = append(acc, collectDuplicateKeys(&root, "")...)

	var file v1alpha1.File
	strict := yaml.NewDecoder(bytes.NewReader(src))
	strict.KnownFields(true)
	if err := strict.Decode(&file); err != nil {
		acc = append(acc, unknownOrDecodeError(origin, err))
	}

	if file.APIVersion == "" {
		acc = append(acc, fieldErr("apiVersion", "required", "apiVersion is required"))
	} else if file.APIVersion != v1alpha1.APIVersion {
		acc = append(acc, fieldErr("apiVersion", "unsupported_version", "unsupported apiVersion"))
	}
	if file.Kind == "" {
		acc = append(acc, fieldErr("kind", "required", "kind is required"))
	} else if file.Kind != v1alpha1.Kind {
		acc = append(acc, fieldErr("kind", "unsupported_kind", "unsupported kind"))
	}

	if len(acc) == 1 {
		return nil, acc[0]
	}
	if len(acc) > 1 {
		out := apperr.New(apperr.CodeConfiguration, "invalid configuration")
		for _, e := range acc {
			for _, f := range e.Fields() {
				out = out.WithField(f)
			}
		}
		return nil, out
	}
	return &file, nil
}

func originOrDoc(origin string) string {
	if origin == "" {
		return "(document)"
	}
	return origin
}

func fieldErr(path, code, msg string) *apperr.Error {
	return apperr.New(apperr.CodeConfiguration, msg).
		WithField(apperr.Field{Path: path, Code: code, Message: msg})
}

func safeYAMLMessage(err error) string {
	msg := err.Error()
	// yaml.v3 sometimes includes a snippet; keep only the type of failure.
	if strings.Contains(msg, "unknown field") {
		return "unknown field"
	}
	if i := strings.Index(msg, "yaml:"); i >= 0 {
		return "yaml syntax error"
	}
	return "yaml decode error"
}

func unknownOrDecodeError(origin string, err error) *apperr.Error {
	msg := err.Error()
	if idx := strings.Index(msg, "field "); idx >= 0 {
		rest := msg[idx+len("field "):]
		name := strings.Trim(strings.Fields(rest)[0], `"`)
		return fieldErr(name, "unknown_field", "unknown field")
	}
	return apperr.New(apperr.CodeConfiguration, "invalid YAML").
		WithField(apperr.Field{Path: originOrDoc(origin), Code: "parse", Message: safeYAMLMessage(err)})
}

func collectDuplicateKeys(n *yaml.Node, path string) []*apperr.Error {
	if n == nil {
		return nil
	}
	var out []*apperr.Error
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			out = append(out, collectDuplicateKeys(c, path)...)
		}
	case yaml.MappingNode:
		seen := map[string]int{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			v := n.Content[i+1]
			key := k.Value
			child := joinPath(path, key)
			if prev, ok := seen[key]; ok {
				_ = prev
				out = append(out, fieldErr(child, "duplicate_key", "duplicate key"))
			} else {
				seen[key] = k.Line
			}
			out = append(out, collectDuplicateKeys(v, child)...)
		}
	case yaml.SequenceNode:
		for i, c := range n.Content {
			out = append(out, collectDuplicateKeys(c, fmt.Sprintf("%s[%d]", path, i))...)
		}
	}
	return out
}

func joinPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}
