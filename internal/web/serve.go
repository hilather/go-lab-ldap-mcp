package web

import (
	"bytes"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// ServeAsset writes a named file from fsys with hashed-asset cache headers.
// It returns false when the path is missing or is a directory so the caller
// can apply SPA index fallback.
func ServeAsset(fsys fs.FS, w http.ResponseWriter, r *http.Request) bool {
	if fsys == nil || r == nil {
		return false
	}
	name, ok := requestAssetName(r.URL.Path)
	if !ok {
		return false
	}
	return serveNamed(fsys, name, w, r) == nil
}

// ServeIndex writes index.html with a revalidate cache policy.
func ServeIndex(fsys fs.FS, w http.ResponseWriter, r *http.Request) {
	if fsys == nil {
		http.NotFound(w, r)
		return
	}
	if err := serveNamed(fsys, "index.html", w, r); err != nil {
		http.NotFound(w, r)
	}
}

func requestAssetName(raw string) (string, bool) {
	cleaned := path.Clean("/" + raw)
	name := strings.TrimPrefix(cleaned, "/")
	if name == "" || name == "." {
		return "", false
	}
	if !fs.ValidPath(name) {
		return "", false
	}
	return name, true
}

func serveNamed(fsys fs.FS, name string, w http.ResponseWriter, r *http.Request) error {
	f, err := fsys.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.IsDir() {
		return fs.ErrNotExist
	}
	var rs io.ReadSeeker
	if seeker, ok := f.(io.ReadSeeker); ok {
		rs = seeker
	} else {
		b, err := io.ReadAll(f)
		if err != nil {
			return err
		}
		rs = bytes.NewReader(b)
	}
	w.Header().Set("Cache-Control", CacheControl(name))
	http.ServeContent(w, r, path.Base(name), st.ModTime(), rs)
	return nil
}
