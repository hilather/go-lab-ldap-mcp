package dirsrv

import (
	"os"
	"path/filepath"
	"strings"
)

// ImageRef returns the pinned 389 DS image from deploy/docker/dirsrv.digest.
func ImageRef() (string, error) {
	root, err := moduleRoot()
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(filepath.Join(root, "deploy", "docker", "dirsrv.digest"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
