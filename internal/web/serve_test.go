package web

import (
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func TestServeAssetHashedAndMissing(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{
		"index.html": {Data: []byte("<!doctype html><title>LabLDAP</title>"), ModTime: time.Unix(1, 0)},
		"assets/index-AbCdEf12.js": {
			Data:    []byte("export{}\n"),
			ModTime: time.Unix(2, 0),
		},
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/assets/index-AbCdEf12.js", nil)
	if !ServeAsset(fsys, rec, req) {
		t.Fatal("expected hashed asset")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != cacheHashed {
		t.Fatalf("Cache-Control = %q", got)
	}
	if rec.Body.String() != "export{}\n" {
		t.Fatalf("body = %q", rec.Body.String())
	}

	miss := httptest.NewRecorder()
	if ServeAsset(fsys, miss, httptest.NewRequest(http.MethodGet, "/users/alice", nil)) {
		t.Fatal("missing UI path must not be served as a file")
	}

	root := httptest.NewRecorder()
	if ServeAsset(fsys, root, httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Fatal("GET / is index fallback, not a named asset")
	}
}

func TestServeIndexRevalidate(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{
		"index.html": {Data: []byte("<!doctype html><p>scaffold</p>"), ModTime: time.Unix(1, 0)},
	}
	rec := httptest.NewRecorder()
	ServeIndex(fsys, rec, httptest.NewRequest(http.MethodGet, "/anything", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != cacheRevalidate {
		t.Fatalf("Cache-Control = %q", got)
	}
	if !strings.Contains(rec.Body.String(), "scaffold") {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestServeIndexMissing(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	ServeIndex(fstest.MapFS{}, rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestFSContainsPlaceholderIndex(t *testing.T) {
	t.Parallel()
	f, err := FS().Open("index.html")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "LabLDAP") {
		t.Fatalf("embedded index = %q", b)
	}
	if _, err := fs.Stat(FS(), "index.html"); err != nil {
		t.Fatal(err)
	}
}
