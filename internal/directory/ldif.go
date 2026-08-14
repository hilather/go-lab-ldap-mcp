package directory

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"sort"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
)

// RFC 2849 line width excluding the CRLF/LF terminator.
const ldifLineWidth = 76

const (
	ldifVersionLine = "version: 1"
	// LDIFCompleteMark is written only after every entry is encoded.
	LDIFCompleteMark = "# labldap: export complete"
	LDIFAbortMark    = "# labldap: export aborted"
)

// Encoder writes RFC 2849 LDIF one entry at a time. It never retains
// previously encoded entries.
type Encoder struct {
	w           io.Writer
	omitSecrets bool
	maxEntries  int
	maxBytes    int64
	wrote       int64
	entries     int
	header      bool
	closed      bool
}

// NewEncoder streams LDIF to w. Zero MaxEntries/MaxBytes mean unlimited.
func NewEncoder(w io.Writer, opts ExportOptions) *Encoder {
	return &Encoder{
		w:           w,
		omitSecrets: opts.OmitSecrets,
		maxEntries:  opts.MaxEntries,
		maxBytes:    opts.MaxBytes,
	}
}

func (e *Encoder) Bytes() int64 {
	if e == nil {
		return 0
	}
	return e.wrote
}

func (e *Encoder) Entries() int {
	if e == nil {
		return 0
	}
	return e.entries
}

// WriteEntry encodes one entry. It checks ctx so a client disconnect
// cancels further directory reads.
func (e *Encoder) WriteEntry(ctx context.Context, ent SearchEntry) error {
	if e == nil || e.w == nil {
		return ExportError("export", FieldUnavailable, "export writer is not configured")
	}
	if e.closed {
		return ExportError("export", FieldConstraint, "encoder is closed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := e.ensureHeader(); err != nil {
		return err
	}
	if e.maxEntries > 0 && e.entries+1 > e.maxEntries {
		return ExportLimit("export.entries", "export entry limit exceeded")
	}
	block := encodeLDIFEntry(ent, e.omitSecrets)
	if e.maxBytes > 0 && e.wrote+int64(len(block)) > e.maxBytes {
		return ExportLimit("export.bytes", "export byte limit exceeded")
	}
	if err := e.writeRaw(block); err != nil {
		return err
	}
	e.entries++
	return nil
}

// Close writes the success trailer. Call only after every entry succeeds.
func (e *Encoder) Close() error {
	if e == nil || e.closed {
		return nil
	}
	if err := e.ensureHeader(); err != nil {
		return err
	}
	line := LDIFCompleteMark + "\n"
	if e.maxBytes > 0 && e.wrote+int64(len(line)) > e.maxBytes {
		return ExportLimit("export.bytes", "export byte limit exceeded")
	}
	if err := e.writeRaw(line); err != nil {
		return err
	}
	e.closed = true
	return nil
}

func (e *Encoder) ensureHeader() error {
	if e.header {
		return nil
	}
	var b strings.Builder
	b.WriteString(ldifVersionLine)
	b.WriteByte('\n')
	b.WriteString("# labldap export\n")
	if e.omitSecrets {
		b.WriteString("# omitSecrets: true\n")
	}
	b.WriteByte('\n')
	if err := e.writeRaw(b.String()); err != nil {
		return err
	}
	e.header = true
	return nil
}

func (e *Encoder) writeRaw(s string) error {
	n, err := io.WriteString(e.w, s)
	e.wrote += int64(n)
	if err != nil {
		return err
	}
	return nil
}

// SecretAttr reports password and other secret attributes omitted by default.
func SecretAttr(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "userpassword", "authpassword",
		"nsmultiplexorbindcred", "nsmultiplexorcredentials",
		"nsds5replicacredentials", "userpkcs12":
		return true
	}
	if strings.Contains(n, "password") || strings.HasPrefix(n, "nsslapd-rootpw") {
		return true
	}
	return false
}

func ExportLimit(path, message string) *apperr.Error {
	return apperr.New(apperr.CodeExport, message).WithField(apperr.Field{
		Path: path, Code: "limit", Message: message,
	})
}

func ExportError(path, code, message string) *apperr.Error {
	e := apperr.New(apperr.CodeExport, message).WithField(apperr.Field{
		Path: path, Code: code, Message: message,
	})
	if code == FieldUnavailable {
		e = e.Retry()
	}
	return e
}

func encodeLDIFEntry(ent SearchEntry, omitSecrets bool) string {
	var b strings.Builder
	writeFolded(&b, encodeLDIFPair("dn", ent.DN))
	for _, g := range groupExportAttrs(ent.Attributes, omitSecrets) {
		for _, v := range g.values {
			writeFolded(&b, encodeLDIFPair(g.name, v))
		}
	}
	b.WriteByte('\n')
	return b.String()
}

type exportAttr struct {
	name   string
	values []string
}

func groupExportAttrs(in []AttrKV, omitSecrets bool) []exportAttr {
	idx := map[string]int{}
	var out []exportAttr
	for _, a := range in {
		name := strings.ToLower(strings.TrimSpace(a.Name))
		if name == "" || name == "dn" {
			continue
		}
		if omitSecrets && SecretAttr(name) {
			continue
		}
		i, ok := idx[name]
		if !ok {
			idx[name] = len(out)
			out = append(out, exportAttr{name: name, values: []string{a.Value}})
			continue
		}
		out[i].values = append(out[i].values, a.Value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	for i := range out {
		sort.Strings(out[i].values)
	}
	return out
}

func encodeLDIFPair(name, value string) string {
	if needsBase64([]byte(value)) {
		return name + ":: " + base64.StdEncoding.EncodeToString([]byte(value))
	}
	return name + ": " + value
}

func needsBase64(v []byte) bool {
	if len(v) == 0 {
		return false
	}
	// RFC 2849: a value that ends with SPACE must be base64 so
	// readers do not strip the trailing blank as fold whitespace.
	if v[len(v)-1] == ' ' {
		return true
	}
	if !safeInitChar(v[0]) {
		return true
	}
	for _, c := range v[1:] {
		if !safeChar(c) {
			return true
		}
	}
	return false
}

func safeInitChar(c byte) bool {
	if c == 0 || c == '\n' || c == '\r' || c == ' ' || c == ':' || c == '<' {
		return false
	}
	return c <= 127
}

func safeChar(c byte) bool {
	if c == 0 || c == '\n' || c == '\r' {
		return false
	}
	return c <= 127
}

func writeFolded(b *strings.Builder, line string) {
	first := true
	rest := line
	for len(rest) > 0 {
		max := ldifLineWidth
		if !first {
			b.WriteByte('\n')
			b.WriteByte(' ')
			max = ldifLineWidth - 1
		}
		if len(rest) <= max {
			b.WriteString(rest)
			break
		}
		b.WriteString(rest[:max])
		rest = rest[max:]
		first = false
	}
	b.WriteByte('\n')
}

// ParseLDIF is a small independent RFC 2849 reader used to prove encoder
// output round-trips. It is not a general LDIF change-record parser.
func ParseLDIF(r io.Reader) ([]SearchEntry, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	raw = bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	raw = unfoldLDIF(raw)
	var out []SearchEntry
	var cur SearchEntry
	have := false
	flush := func() {
		if !have {
			return
		}
		out = append(out, cur)
		cur = SearchEntry{}
		have = false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "#") || line == "" {
			if line == "" {
				flush()
			}
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "version:") {
			continue
		}
		name, value, ok := splitLDIFLine(line)
		if !ok {
			continue
		}
		if name == "dn" {
			flush()
			cur.DN = value
			have = true
			continue
		}
		if !have {
			continue
		}
		cur.Attributes = append(cur.Attributes, AttrKV{Name: name, Value: value})
	}
	flush()
	return out, nil
}

func unfoldLDIF(in []byte) []byte {
	var out []byte
	for i := 0; i < len(in); i++ {
		if in[i] == '\n' && i+1 < len(in) && in[i+1] == ' ' {
			i++
			continue
		}
		out = append(out, in[i])
	}
	return out
}

func splitLDIFLine(line string) (name, value string, ok bool) {
	if i := strings.Index(line, ":: "); i >= 1 {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line[i+3:]))
		if err != nil {
			return "", "", false
		}
		return strings.ToLower(strings.TrimSpace(line[:i])), string(raw), true
	}
	if i := strings.Index(line, ": "); i >= 1 {
		return strings.ToLower(strings.TrimSpace(line[:i])), line[i+2:], true
	}
	if i := strings.IndexByte(line, ':'); i >= 1 {
		return strings.ToLower(strings.TrimSpace(line[:i])), "", true
	}
	return "", "", false
}
