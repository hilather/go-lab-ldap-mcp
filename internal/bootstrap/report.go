package bootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
)

// PhaseResult is one executed bootstrap phase. Counts must be secret-free.
type PhaseResult struct {
	Phase      string         `json:"phase"`
	DurationMS int64          `json:"duration_ms"`
	Counts     map[string]int `json:"counts,omitempty"`
	OK         bool           `json:"ok"`
	Code       string         `json:"code,omitempty"`
}

// Summary is the redacted JSON document written to stdout at the end.
type Summary struct {
	Command           string          `json:"command"`
	Source            string          `json:"source,omitempty"`
	Mode              string          `json:"mode,omitempty"`
	OK                bool            `json:"ok"`
	Phases            []PhaseResult   `json:"phases"`
	Remaining         []string        `json:"remaining,omitempty"`
	Plan              json.RawMessage `json:"plan,omitempty"`
	DirectoryRevision string          `json:"directoryRevision,omitempty"`
}

func (s Summary) JSON() ([]byte, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, b, "", "  "); err != nil {
		return nil, err
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

type reporter struct {
	log    *slog.Logger
	phases []PhaseResult
}

func (r *reporter) run(name string, fn func() (map[string]int, error)) error {
	start := time.Now()
	counts, err := fn()
	pr := PhaseResult{
		Phase:      name,
		DurationMS: time.Since(start).Milliseconds(),
		Counts:     counts,
		OK:         err == nil,
	}
	if err != nil {
		pr.Code = firstFieldCode(err)
	}
	r.phases = append(r.phases, pr)
	if r.log != nil {
		r.log.Info("bootstrap phase",
			"phase", name,
			"duration_ms", pr.DurationMS,
			"ok", pr.OK,
		)
	}
	return err
}

func firstFieldCode(err error) string {
	var e *apperr.Error
	if !errors.As(err, &e) || e == nil {
		return ""
	}
	if fs := e.Fields(); len(fs) > 0 {
		return fs[0].Code
	}
	return string(e.Code())
}
