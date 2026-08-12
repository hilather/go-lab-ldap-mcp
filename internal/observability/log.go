package observability

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

const (
	FormatText = "text"
	FormatJSON = "json"
)

// FormatFromEnv reads LABLDAP_LOG_FORMAT (json|text). Default is text.
func FormatFromEnv() string {
	return NormalizeFormat(os.Getenv("LABLDAP_LOG_FORMAT"))
}

func NormalizeFormat(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case FormatJSON:
		return FormatJSON
	default:
		return FormatText
	}
}

// NewLogger returns a slog logger that always attaches component and version.
func NewLogger(w io.Writer, format string, info BuildInfo) *slog.Logger {
	if w == nil {
		w = io.Discard
	}
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	var h slog.Handler
	if NormalizeFormat(format) == FormatJSON {
		h = slog.NewJSONHandler(w, opts)
	} else {
		h = slog.NewTextHandler(w, opts)
	}
	return slog.New(h).With(
		slog.String("component", info.Component),
		slog.String("version", info.Version),
		slog.String("revision", info.Revision),
	)
}
