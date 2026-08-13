package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

var laterPhases = []string{
	"inspect",
	"aci", "seed", "verify_runtime", "verify_app", "drift", "marker",
}

// Options is the parsed bootstrap command.
type Options struct {
	Command        string
	ConfigPath     string
	PasswordFile   string
	LDAPURL        string
	CAFile         string
	DirectoryHost  string
	Deadline       time.Duration
	DSConfInstance string
	Waiter         Waiter
	Backend        BackendReconciler
	TLS            TLSReconciler
	Policy         PolicyReconciler
	Plugins        PluginReconciler
	Tree           TreeReconciler
	RequireSASL    []string
	Log            *slog.Logger
	Now            func() time.Time
}

// Run executes apply, validate, or plan. Exit codes are returned separately
// from the JSON summary so the CLI can print both.
func Run(ctx context.Context, opt Options, stdout, stderr io.Writer) (Summary, error) {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Deadline <= 0 {
		opt.Deadline = 90 * time.Second
	}
	if opt.DirectoryHost == "" {
		opt.DirectoryHost = "127.0.0.1"
	}
	if opt.DSConfInstance == "" {
		opt.DSConfInstance = "localhost"
	}
	if opt.Log == nil {
		opt.Log = slog.New(slog.NewJSONHandler(stderr, nil))
	}

	rep := &reporter{log: opt.Log}
	sum := Summary{Command: opt.Command, Source: opt.ConfigPath}

	var compiled *config.Compiled
	err := rep.run("load", func() (map[string]int, error) {
		c, e := loadConfig(ctx, opt)
		if e != nil {
			return nil, e
		}
		compiled = c
		return map[string]int{
			"users":  len(c.Normalized.Users),
			"groups": len(c.Normalized.Groups),
			"acis":   len(c.Data.ACIs),
		}, nil
	})
	if err != nil {
		sum.Phases = rep.phases
		return sum, err
	}
	sum.Mode = compiled.Normalized.StartupMode
	sum.DirectoryRevision = compiled.Revisions.Directory
	if plan, e := compiled.RedactedJSON(); e == nil {
		sum.Plan = json.RawMessage(plan)
	}

	if opt.Command == "plan" {
		sum.OK = true
		sum.Phases = rep.phases
		return sum, nil
	}

	err = rep.run("wait", func() (map[string]int, error) {
		if opt.Waiter == nil {
			return nil, phaseErr("wait", "waiter_missing", "directory waiter is not configured")
		}
		pw, e := readPasswordFile(opt.PasswordFile)
		if e != nil {
			return nil, e
		}
		req := waitRequestFrom(compiled, opt, pw)
		res, e := opt.Waiter.Wait(ctx, req)
		if e != nil {
			return nil, e
		}
		return map[string]int{"namingContexts": res.NamingContexts}, nil
	})
	if err != nil {
		sum.Phases = rep.phases
		return sum, err
	}

	write := opt.Command == "apply" && compiled.Normalized.StartupMode != v1alpha1.StartupValidate
	err = rep.run("backend", func() (map[string]int, error) {
		if opt.Backend == nil {
			return nil, phaseErr("backend", "create_failed", "backend reconciler is not configured")
		}
		res, e := opt.Backend.Reconcile(ctx, BackendRequest{
			PasswordFile: opt.PasswordFile,
			Instance:     opt.DSConfInstance,
			Name:         compiled.Engine.BackendName,
			Suffix:       compiled.Engine.Suffix,
			Write:        write,
		})
		if e != nil {
			return nil, e
		}
		counts := map[string]int{"backends": 1}
		switch res.Action {
		case "created":
			counts["created"] = 1
		case "matched":
			counts["matched"] = 1
		}
		return counts, nil
	})
	if err != nil {
		sum.Phases = rep.phases
		return sum, err
	}

	err = rep.run("tls", func() (map[string]int, error) {
		if opt.TLS == nil {
			return nil, phaseErr("tls", "tls", "tls reconciler is not configured")
		}
		pw, e := readPasswordFile(opt.PasswordFile)
		if e != nil {
			return nil, e
		}
		res, e := opt.TLS.ReconcileTLS(ctx, tlsRequestFrom(compiled, opt, pw, write))
		if e != nil {
			return nil, e
		}
		return map[string]int{"transports": len(res.Transports), "sasl": len(res.SASL)}, nil
	})
	if err != nil {
		sum.Phases = rep.phases
		return sum, err
	}

	err = rep.run("pwpolicy", func() (map[string]int, error) {
		if opt.Policy == nil {
			return nil, phaseErr("pwpolicy", "readback_mismatch", "password policy reconciler is not configured")
		}
		res, e := opt.Policy.ReconcilePolicy(ctx, PolicyRequest{
			PasswordFile: opt.PasswordFile,
			Instance:     opt.DSConfInstance,
			Policy:       compiled.Normalized.Policy,
			Write:        write,
		})
		if e != nil {
			return nil, e
		}
		return map[string]int{"applied": len(res.Applied)}, nil
	})
	if err != nil {
		sum.Phases = rep.phases
		return sum, err
	}

	err = rep.run("plugins", func() (map[string]int, error) {
		if opt.Plugins == nil {
			return nil, phaseErr("plugins", "plugin_missing", "plugin reconciler is not configured")
		}
		res, e := opt.Plugins.ReconcilePlugins(ctx, PluginRequest{
			PasswordFile: opt.PasswordFile,
			Instance:     opt.DSConfInstance,
			Suffix:       compiled.Engine.Suffix,
			Plugins:      compiled.Engine.Plugins,
			Write:        write,
		})
		if e != nil {
			return nil, e
		}
		return map[string]int{"applied": len(res.Applied)}, nil
	})
	if err != nil {
		sum.Phases = rep.phases
		return sum, err
	}

	err = rep.run("tree", func() (map[string]int, error) {
		if opt.Tree == nil {
			return nil, phaseErr("tree", "parent_failed", "tree reconciler is not configured")
		}
		pw, e := readPasswordFile(opt.PasswordFile)
		if e != nil {
			return nil, e
		}
		res, e := opt.Tree.ReconcileTree(ctx, treeRequestFrom(compiled, opt, pw, write))
		if e != nil {
			return nil, e
		}
		return map[string]int{"created": len(res.Created), "matched": len(res.Matched)}, nil
	})
	sum.Phases = rep.phases
	if err != nil {
		return sum, err
	}
	sum.Remaining = laterPhases
	sum.OK = true
	return sum, nil
}

func loadConfig(ctx context.Context, opt Options) (*config.Compiled, error) {
	src, err := os.ReadFile(opt.ConfigPath)
	if err != nil {
		return nil, apperr.New(apperr.CodeConfiguration, "configuration file unreadable").
			WithField(apperr.Field{Path: "config", Code: "unreadable", Message: "path could not be read"})
	}
	compiled, err := config.Compile(ctx, src, opt.ConfigPath, config.LoadOptions{
		Caller:  config.CallerBootstrap,
		Secrets: config.DirSecretResolver(filepath.Dir(opt.ConfigPath)),
	})
	if err != nil {
		return nil, err
	}
	return compiled, nil
}

func readPasswordFile(path string) (observability.Secret, error) {
	res, err := config.FileSecretResolver().Resolve(context.Background(), "directory-manager-password-file", path)
	if err != nil {
		var e *apperr.Error
		if errors.As(err, &e) {
			code := "secret_unreadable"
			if fs := e.Fields(); len(fs) > 0 && fs[0].Code != "" {
				code = fs[0].Code
			}
			return "", phaseErr("wait", code, e.PublicMessage()).Wrap(err)
		}
		return "", phaseErr("wait", "secret_unreadable", "Directory Manager password file unreadable").Wrap(err)
	}
	return res.Value, nil
}

func waitRequestFrom(c *config.Compiled, opt Options, pw observability.Secret) WaitRequest {
	pub := c.Public
	req := WaitRequest{
		Host:        opt.DirectoryHost,
		LDAPPort:    pub.Spec.Transport.LDAP.Port,
		LDAPSPort:   pub.Spec.Transport.LDAPS.Port,
		UseLDAPS:    pub.Spec.Transport.LDAPS.Enabled,
		StartTLS:    pub.Spec.Transport.StartTLS,
		Insecure:    pub.Spec.Transport.InsecureLabMode,
		CAFile:      opt.CAFile,
		BindDN:      defaultBindDN,
		Password:    pw,
		DialTimeout: 5 * time.Second,
		Deadline:    opt.Deadline,
	}
	if d, err := time.ParseDuration(pub.Spec.Limits.LDAPDialTimeout); err == nil && d > 0 {
		req.DialTimeout = d
	}
	req.LDAPURL = opt.LDAPURL
	return req
}

func tlsRequestFrom(c *config.Compiled, opt Options, pw observability.Secret, write bool) TLSRequest {
	pub := c.Public
	dialHost := "127.0.0.1"
	if opt.LDAPURL != "" {
		u := strings.TrimPrefix(strings.TrimPrefix(opt.LDAPURL, "ldaps://"), "ldap://")
		if h, _, err := net.SplitHostPort(u); err == nil && h != "" {
			dialHost = h
		}
	}
	ldapPort := pub.Spec.Transport.LDAP.Port
	if ldapPort == 0 {
		ldapPort = 3389
	}
	ldapsPort := pub.Spec.Transport.LDAPS.Port
	if ldapsPort == 0 {
		ldapsPort = 3636
	}
	return TLSRequest{
		PasswordFile:   opt.PasswordFile,
		Instance:       opt.DSConfInstance,
		LDAPURL:        opt.LDAPURL,
		LDAPAddr:       net.JoinHostPort(dialHost, fmt.Sprintf("%d", ldapPort)),
		LDAPSAddr:      net.JoinHostPort(dialHost, fmt.Sprintf("%d", ldapsPort)),
		CAFile:         opt.CAFile,
		Host:           opt.DirectoryHost,
		UseLDAPS:       pub.Spec.Transport.LDAPS.Enabled,
		StartTLS:       pub.Spec.Transport.StartTLS,
		Insecure:       pub.Spec.Transport.InsecureLabMode,
		AllowCleartext: pub.Spec.Transport.AllowCleartextBind,
		AllowAnonymous: pub.Spec.Transport.AllowAnonymousBind,
		RequiredSASL:   append([]string(nil), opt.RequireSASL...),
		BindDN:         defaultBindDN,
		Password:       pw,
		Write:          write,
		DialTimeout:    5 * time.Second,
	}
}

func treeRequestFrom(c *config.Compiled, opt Options, dm observability.Secret, write bool) TreeRequest {
	tls := tlsRequestFrom(c, opt, dm, write)
	n := c.Normalized
	return TreeRequest{
		Suffix:          n.Suffix.String(),
		PeopleDN:        n.PeopleDN.String(),
		GroupsDN:        n.GroupsDN.String(),
		RuntimeDN:       n.Runtime.DN,
		RuntimePassword: n.Runtime.Password.Value,
		DMPassword:      dm,
		LDAPURL:         tls.LDAPURL,
		LDAPAddr:        tls.LDAPAddr,
		LDAPSAddr:       tls.LDAPSAddr,
		CAFile:          tls.CAFile,
		Host:            tls.Host,
		UseLDAPS:        tls.UseLDAPS,
		StartTLS:        tls.StartTLS,
		Insecure:        tls.Insecure,
		Write:           write,
		DialTimeout:     tls.DialTimeout,
	}
}

// WriteSummary prints the JSON summary and a short public error line.
func WriteSummary(stdout, stderr io.Writer, sum Summary, err error) {
	if err != nil {
		fmt.Fprintf(stderr, "labldap-bootstrap: %s\n", publicLine(err))
		var e *apperr.Error
		if errors.As(err, &e) {
			for _, f := range e.Fields() {
				fmt.Fprintf(stderr, "  %s: %s (%s)\n", f.Path, f.Message, f.Code)
			}
		}
	}
	b, jerr := sum.JSON()
	if jerr != nil {
		fmt.Fprintf(stderr, "labldap-bootstrap: failed to encode summary\n")
		return
	}
	_, _ = stdout.Write(b)
}

func publicLine(err error) string {
	if msg := apperr.PublicMessageOf(err); msg != "" {
		return msg
	}
	return "bootstrap failed"
}

func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	return 1
}
