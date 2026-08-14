package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestServeRequiresPlaceholder(t *testing.T) {
	t.Setenv("LABLDAP_LOG_FORMAT", "text")
	var stdout, stderr strings.Builder
	code := run([]string{"serve"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d, want 2; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--placeholder") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestServeUnknownFlag(t *testing.T) {
	var stdout, stderr strings.Builder
	code := run([]string{"serve", "--placeholder", "--listen", "0.0.0.0:1"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "unknown flag") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestListenAddrEnvOnly(t *testing.T) {
	t.Setenv("LABLDAP_LISTEN", "")
	if got := listenAddr(); got != defaultListen {
		t.Fatalf("default = %q", got)
	}
	t.Setenv("LABLDAP_LISTEN", " 10.0.0.5:9000 ")
	if got := listenAddr(); got != "10.0.0.5:9000" {
		t.Fatalf("env = %q", got)
	}
}

func TestPlaceholderHealth(t *testing.T) {
	h := placeholderHandler()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	live := httptest.NewRecorder()
	h.ServeHTTP(live, req)
	if live.Code != http.StatusOK {
		t.Fatalf("liveness %d", live.Code)
	}
	ready := httptest.NewRecorder()
	h.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness %d", ready.Code)
	}
}

func TestPlaceholderGracefulShutdown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- servePlaceholderListener(ctx, ln) }()

	deadline := time.Now().Add(3 * time.Second)
	var live *http.Response
	for time.Now().Before(deadline) {
		live, err = http.Get("http://" + addr + "/health")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("liveness: %v", err)
	}
	_, _ = io.Copy(io.Discard, live.Body)
	_ = live.Body.Close()
	if live.StatusCode != http.StatusOK {
		t.Fatalf("liveness %d", live.StatusCode)
	}

	ready, err := http.Get("http://" + addr + "/health/ready")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, ready.Body)
	_ = ready.Body.Close()
	if ready.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("readiness %d", ready.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown timed out")
	}
}
