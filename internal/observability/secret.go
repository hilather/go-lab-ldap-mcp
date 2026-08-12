package observability

import (
	"encoding/json"
	"log/slog"
)

const redacted = "[redacted]"

// Secret is a sensitive string that must never appear in logs, fmt output,
// or JSON. Use it for tokens, passwords, session IDs, and secret-file contents.
type Secret string

func (s Secret) String() string { return redacted }

func (s Secret) GoString() string { return "observability.Secret{}" }

func (s Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

func (s Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

func (s Secret) MarshalJSON() ([]byte, error) { return json.Marshal(redacted) }

// Reveal returns the raw value. Callers must not log or format the result.
func (s Secret) Reveal() string { return string(s) }
