package web

import "testing"

func TestIsHashedAsset(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		want bool
	}{
		{name: "assets/index-AbCdEf12.js", want: true},
		{name: "/assets/index-AbCdEf12.css", want: true},
		{name: "assets/logo-9f8e7d6c.svg", want: true},
		{name: "index.html", want: false},
		{name: "/index.html", want: false},
		{name: "favicon.svg", want: false},
		{name: "assets/logo.svg", want: false},
		{name: "assets/index.js", want: false},
		{name: "", want: false},
		{name: ".", want: false},
		{name: "/", want: false},
	}
	for _, tc := range cases {
		if got := IsHashedAsset(tc.name); got != tc.want {
			t.Errorf("IsHashedAsset(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestCacheControl(t *testing.T) {
	t.Parallel()
	if got := CacheControl("assets/index-AbCdEf12.js"); got != cacheHashed {
		t.Fatalf("hashed Cache-Control = %q", got)
	}
	if got := CacheControl("index.html"); got != cacheRevalidate {
		t.Fatalf("index Cache-Control = %q", got)
	}
}
