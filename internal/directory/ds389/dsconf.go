package ds389

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// ExecFunc runs a command by name and argv. Tests replace this; production
// uses exec.CommandContext. Callers must never pass the password in args.
type ExecFunc func(ctx context.Context, name string, args []string) (stdout, stderr []byte, err error)

// Runner invokes dsconf with an argument vector and a password file (-y).
type Runner struct {
	Bin  string
	Exec ExecFunc
}

func defaultExec(ctx context.Context, name string, args []string) (stdout, stderr []byte, err error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err = cmd.Run()
	return out.Bytes(), errb.Bytes(), err
}

func (r Runner) bin() string {
	if r.Bin != "" {
		return r.Bin
	}
	return "dsconf"
}

func (r Runner) exec() ExecFunc {
	if r.Exec != nil {
		return r.Exec
	}
	return defaultExec
}

// JSON runs dsconf -j with -D and -y. The password value is never placed on argv.
func (r Runner) JSON(ctx context.Context, pwdFile, instance string, sub []string) ([]byte, error) {
	if pwdFile == "" {
		return nil, fmt.Errorf("dsconf password file is required")
	}
	if instance == "" {
		instance = "localhost"
	}
	args := []string{"-D", "cn=Directory Manager", "-y", pwdFile, "-j", instance}
	args = append(args, sub...)
	out, errb, err := r.exec()(ctx, r.bin(), args)
	if err != nil {
		msg := strings.TrimSpace(string(out) + "\n" + string(errb))
		return out, fmt.Errorf("dsconf %s: %w: %s", strings.Join(sub, " "), err, compactJSONDesc(out, msg))
	}
	return out, nil
}

func compactJSONDesc(raw []byte, fallback string) string {
	var obj struct {
		Desc string `json:"desc"`
	}
	if json.Unmarshal(raw, &obj) == nil && obj.Desc != "" {
		return obj.Desc
	}
	s := strings.TrimSpace(fallback)
	if len(s) > 240 {
		s = s[:240]
	}
	return s
}
