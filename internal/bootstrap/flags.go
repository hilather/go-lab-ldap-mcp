package bootstrap

import (
	"fmt"
	"strings"
	"time"
)

// ParseArgs parses apply/validate/plan flags. Usage errors are returned as
// *UsageError (CLI exit 2). A bare --directory-manager-password is always
// a usage error.
type UsageError struct {
	Msg string
}

func (e *UsageError) Error() string { return e.Msg }

func ParseArgs(cmd string, args []string) (Options, error) {
	opt := Options{Command: cmd, DirectoryHost: "127.0.0.1", Deadline: 90 * time.Second}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--directory-manager-password" || strings.HasPrefix(a, "--directory-manager-password="):
			return Options{}, &UsageError{Msg: "Directory Manager password must be passed as --directory-manager-password-file, not a command-line value"}
		case a == "--config" || a == "-c":
			v, err := takeValue(args, &i, a)
			if err != nil {
				return Options{}, err
			}
			opt.ConfigPath = v
		case strings.HasPrefix(a, "--config="):
			opt.ConfigPath = strings.TrimPrefix(a, "--config=")
		case a == "--directory-manager-password-file":
			v, err := takeValue(args, &i, a)
			if err != nil {
				return Options{}, err
			}
			opt.PasswordFile = v
		case strings.HasPrefix(a, "--directory-manager-password-file="):
			opt.PasswordFile = strings.TrimPrefix(a, "--directory-manager-password-file=")
		case a == "--ldap-url":
			v, err := takeValue(args, &i, a)
			if err != nil {
				return Options{}, err
			}
			opt.LDAPURL = v
		case strings.HasPrefix(a, "--ldap-url="):
			opt.LDAPURL = strings.TrimPrefix(a, "--ldap-url=")
		case a == "--directory-ca-file":
			v, err := takeValue(args, &i, a)
			if err != nil {
				return Options{}, err
			}
			opt.CAFile = v
		case strings.HasPrefix(a, "--directory-ca-file="):
			opt.CAFile = strings.TrimPrefix(a, "--directory-ca-file=")
		case a == "--directory-host":
			v, err := takeValue(args, &i, a)
			if err != nil {
				return Options{}, err
			}
			opt.DirectoryHost = v
		case strings.HasPrefix(a, "--directory-host="):
			opt.DirectoryHost = strings.TrimPrefix(a, "--directory-host=")
		case a == "--deadline":
			v, err := takeValue(args, &i, a)
			if err != nil {
				return Options{}, err
			}
			d, perr := time.ParseDuration(v)
			if perr != nil || d <= 0 {
				return Options{}, &UsageError{Msg: "invalid --deadline"}
			}
			opt.Deadline = d
		case strings.HasPrefix(a, "--deadline="):
			d, perr := time.ParseDuration(strings.TrimPrefix(a, "--deadline="))
			if perr != nil || d <= 0 {
				return Options{}, &UsageError{Msg: "invalid --deadline"}
			}
			opt.Deadline = d
		case a == "--dsconf-instance":
			v, err := takeValue(args, &i, a)
			if err != nil {
				return Options{}, err
			}
			opt.DSConfInstance = v
		case strings.HasPrefix(a, "--dsconf-instance="):
			opt.DSConfInstance = strings.TrimPrefix(a, "--dsconf-instance=")
		default:
			return Options{}, &UsageError{Msg: fmt.Sprintf("unknown flag %q", a)}
		}
	}
	if opt.ConfigPath == "" {
		return Options{}, &UsageError{Msg: "--config is required"}
	}
	if cmd != "plan" && opt.PasswordFile == "" {
		return Options{}, &UsageError{Msg: "--directory-manager-password-file is required"}
	}
	return opt, nil
}

func takeValue(args []string, i *int, flag string) (string, error) {
	if *i+1 >= len(args) {
		return "", &UsageError{Msg: flag + " requires a value"}
	}
	*i++
	return args[*i], nil
}
