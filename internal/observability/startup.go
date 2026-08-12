package observability

import (
	"fmt"
	"io"
	"log/slog"
)

// StartupLogger writes a starting record with component and version fields.
func StartupLogger(w io.Writer, component string) (BuildInfo, *slog.Logger) {
	info := CurrentBuild(component)
	log := NewLogger(w, FormatFromEnv(), info)
	log.Info("starting")
	return info, log
}

func WriteVersion(w io.Writer, info BuildInfo) {
	fmt.Fprintf(w, "component=%s version=%s revision=%s time=%s\n",
		info.Component, info.Version, info.Revision, info.Time)
}
