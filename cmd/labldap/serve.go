package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const defaultListen = "127.0.0.1:8443"

func runServe(args []string, stdout, stderr io.Writer) int {
	_ = stdout
	placeholder := false
	for _, a := range args {
		switch a {
		case "--placeholder":
			placeholder = true
		default:
			fmt.Fprintf(stderr, "labldap: unknown flag %q\n", a)
			return 2
		}
	}
	if !placeholder {
		fmt.Fprintln(stderr, "labldap: serve requires --placeholder until the real HTTP stack lands")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := servePlaceholder(ctx, listenAddr(), stderr); err != nil {
		fmt.Fprintf(stderr, "labldap: %v\n", err)
		return 1
	}
	return 0
}

// listenAddr is LABLDAP_LISTEN only (KD-R19). It does not read YAML.
func listenAddr() string {
	if v := strings.TrimSpace(os.Getenv("LABLDAP_LISTEN")); v != "" {
		return v
	}
	return defaultListen
}

// placeholderHandler is liveness/readiness only. No LDAP, no config.Compile.
func placeholderHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "not ready\n")
	})
	return mux
}

func servePlaceholder(ctx context.Context, addr string, stderr io.Writer) error {
	_ = stderr
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return servePlaceholderListener(ctx, ln)
}

func servePlaceholderListener(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           placeholderHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
			return
		}
		errc <- nil
	}()
	select {
	case <-ctx.Done():
		shctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shctx)
		return <-errc
	case err := <-errc:
		return err
	}
}
