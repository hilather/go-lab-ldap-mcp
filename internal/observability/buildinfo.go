package observability

import (
	"log/slog"
	"runtime/debug"
	"sync"
)

// Set by -ldflags at release builds. Dev builds fall back to module info.
var (
	version  = "dev"
	revision = ""
	builtAt  = ""
)

type BuildInfo struct {
	Version   string
	Revision  string
	Time      string
	Component string
}

func (b BuildInfo) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("version", b.Version),
		slog.String("revision", b.Revision),
		slog.String("time", b.Time),
		slog.String("component", b.Component),
	)
}

var readBuildOnce sync.Once
var cachedRevision string
var cachedTime string

func CurrentBuild(component string) BuildInfo {
	readBuildOnce.Do(func() {
		cachedRevision = revision
		cachedTime = builtAt
		if cachedRevision != "" && cachedTime != "" {
			return
		}
		info, ok := debug.ReadBuildInfo()
		if !ok {
			return
		}
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if cachedRevision == "" {
					cachedRevision = s.Value
					if len(cachedRevision) > 12 {
						cachedRevision = cachedRevision[:12]
					}
				}
			case "vcs.time":
				if cachedTime == "" {
					cachedTime = s.Value
				}
			}
		}
	})
	rev := cachedRevision
	if rev == "" {
		rev = "unknown"
	}
	when := cachedTime
	if when == "" {
		when = "unknown"
	}
	return BuildInfo{
		Version:   version,
		Revision:  rev,
		Time:      when,
		Component: component,
	}
}
