//go:build integration

package dirsrv

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func TestApplyCommandOutputSeparatesDiagnostics(t *testing.T) {
	for _, script := range []string{
		`printf 'stderr-before-canary\n' >&2; printf '{"command":"apply","ok":true}\n'; printf 'stderr-after-canary\n' >&2`,
		`printf '{"command":"apply","ok":true}\n'; printf 'stderr-after-canary\n' >&2`,
	} {
		out, err := applyCommandOutput(exec.CommandContext(t.Context(), "sh", "-c", script))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, "stderr-after-canary") {
			t.Fatal("stderr lost from canary transcript")
		}
		start := strings.Index(out, "{")
		var summary struct {
			OK bool `json:"ok"`
		}
		if err := json.Unmarshal([]byte(out[start:]), &summary); err != nil || !summary.OK {
			t.Fatalf("summary contaminated by stderr: %v\n%s", err, out)
		}
	}
}

func TestApplyCommandOutputRejectsInvalidStdout(t *testing.T) {
	for _, stdout := range []string{`{"ok":true}trailing`, `{"ok":`, `[]`, ``} {
		cmd := exec.CommandContext(t.Context(), "sh", "-c", `printf '%s' "$1"; printf 'diagnostic-canary' >&2`, "test", stdout)
		out, err := applyCommandOutput(cmd)
		if err == nil {
			t.Fatalf("accepted invalid summary %q", stdout)
		}
		if !strings.Contains(out, stdout) || !strings.Contains(out, "diagnostic-canary") {
			t.Fatal("failure diagnostics lost")
		}
	}
	out, err := applyCommandOutput(exec.CommandContext(t.Context(), "sh", "-c", `printf 'failed stdout'; printf 'failed stderr' >&2; exit 42`))
	if err == nil || !strings.Contains(out, "failed stdout") || !strings.Contains(out, "failed stderr") {
		t.Fatalf("exit error or diagnostics lost: %v %q", err, out)
	}
}
