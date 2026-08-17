// labldap-setup-tls generates a lab CA and directory certificates (T-113).
// Import uses dsctl tls import-* after first boot. The private CA key is
// never copied into a runtime container.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	caName    = "LabLDAP-Lab-CA"
	usageText = `labldap-setup-tls — lab CA and directory TLS (T-113)

generate writes a private CA and SAN certificates. import copies only the
CA certificate and directory server key/cert into the running directory
container (never the CA private key) and runs dsctl tls import-* after
first boot.

Usage:
  labldap-setup-tls generate [--dir secrets/tls] [--host directory] [--force] [--management]
  labldap-setup-tls import   [--dir secrets/tls] [--project labldap] [--service directory] [-f FILE]...
  labldap-setup-tls import   --container NAME [--dir secrets/tls]
  labldap-setup-tls publish  [--out secrets/tls/instance-ca.crt] [--project labldap] [--service directory] [-f FILE]...

import defaults to the persistent Compose overlay. It refuses a tmpfs-backed
/data (restart remounts empty) and checks dsctl show-server-cert after
restart. publish writes the instance CA to instance-ca.crt and refuses to
overwrite ca.crt when ca.key is present.
`
)

type material struct {
	Dir            string
	CACert         string
	CAKey          string
	DirectoryCert  string
	DirectoryKey   string
	ManagementCert string
	ManagementKey  string
}

func paths(dir string) material {
	return material{
		Dir:            dir,
		CACert:         filepath.Join(dir, "ca.crt"),
		CAKey:          filepath.Join(dir, "ca.key"),
		DirectoryCert:  filepath.Join(dir, "directory.crt"),
		DirectoryKey:   filepath.Join(dir, "directory.key"),
		ManagementCert: filepath.Join(dir, "management.crt"),
		ManagementKey:  filepath.Join(dir, "management.key"),
	}
}

// RuntimeTrustFiles are the only TLS files that belong on control/bootstrap.
func RuntimeTrustFiles(dir string) []string {
	return []string{paths(dir).CACert}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(stdout, usageText)
		return 0
	}
	cmd := args[0]
	rest := args[1:]
	switch cmd {
	case "generate":
		return runGenerate(rest, stdout, stderr)
	case "import":
		return runImport(rest, stdout, stderr)
	case "publish":
		return runPublish(rest, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "setuptls: unknown command %q\n", cmd)
		fmt.Fprint(stderr, usageText)
		return 2
	}
}

func runGenerate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "secrets/tls", "output directory")
	host := fs.String("host", "directory", "directory certificate DNS SAN")
	force := fs.Bool("force", false, "overwrite existing PEMs")
	mgmt := fs.Bool("management", false, "also write optional management SAN cert")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprint(stdout, usageText)
			return 0
		}
		return 2
	}
	if err := generate(*dir, *host, *force, *mgmt, stdout); err != nil {
		fmt.Fprintf(stderr, "setuptls generate: %v\n", err)
		return 1
	}
	return 0
}

func generate(dir, host string, force, management bool, stdout io.Writer) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	p := paths(dir)
	if !force {
		for _, f := range []string{p.CACert, p.CAKey, p.DirectoryCert, p.DirectoryKey} {
			if fileExists(f) {
				fmt.Fprintf(stdout, "skipped %s (exists)\n", f)
				return nil
			}
		}
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: caName, Organization: []string{"LabLDAP"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	if err := writePEM(p.CACert, "CERTIFICATE", caDER, 0o644); err != nil {
		return err
	}
	if err := writePEM(p.CAKey, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(caKey), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote %s\n", p.CACert)
	fmt.Fprintf(stdout, "wrote %s\n", p.CAKey)

	sans := []string{host, "localhost"}
	if err := signServer(p.DirectoryCert, p.DirectoryKey, caTmpl, caKey, host, sans, []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote %s\n", p.DirectoryCert)
	fmt.Fprintf(stdout, "wrote %s\n", p.DirectoryKey)

	if management {
		if err := signServer(p.ManagementCert, p.ManagementKey, caTmpl, caKey, "control", []string{"control", "localhost"}, []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "wrote %s\n", p.ManagementCert)
		fmt.Fprintf(stdout, "wrote %s\n", p.ManagementKey)
	}
	return nil
}

func signServer(certPath, keyPath string, ca *x509.Certificate, caKey *rsa.PrivateKey, cn string, dns []string, ips []net.IP) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	return writePEM(keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), 0o600)
}

func runImport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "secrets/tls", "certificate directory")
	project := fs.String("project", "labldap", "Compose project name")
	service := fs.String("service", "directory", "directory service name")
	container := fs.String("container", "", "raw docker container (skips Compose)")
	var files multiFlag
	fs.Var(&files, "f", "Compose file (repeatable)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprint(stdout, usageText)
			return 0
		}
		return 2
	}
	if len(files) == 0 {
		files = defaultImportComposeFiles()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var err error
	if *container != "" {
		err = importTLSContainer(ctx, *dir, *container, stdout)
	} else {
		err = importTLS(ctx, *dir, *project, *service, files, stdout)
	}
	if err != nil {
		fmt.Fprintf(stderr, "setuptls import: %v\n", err)
		return 1
	}
	return 0
}

func defaultImportComposeFiles() []string {
	return []string{"deploy/compose/compose.389ds.yaml", "deploy/compose/compose.389ds-persistent.yaml"}
}

func importTLS(ctx context.Context, dir, project, service string, composeFiles []string, stdout io.Writer) error {
	p := paths(dir)
	for _, f := range []string{p.CACert, p.DirectoryCert, p.DirectoryKey} {
		if !fileExists(f) {
			return fmt.Errorf("missing %s (run generate first)", f)
		}
	}
	if fileExists(p.CAKey) {
		// Never copy the CA private key. Presence on the host is expected.
		fmt.Fprintf(stdout, "ca private key stays on host: %s\n", p.CAKey)
	}
	compose := composeArgs(project, composeFiles)
	if err := waitFirstBoot(ctx, compose, service); err != nil {
		return err
	}
	cid, err := dockerOutput(ctx, append(compose, "ps", "-q", service)...)
	if err != nil {
		return err
	}
	if err := refuseTmpfsData(ctx, strings.TrimSpace(string(cid))); err != nil {
		return err
	}
	if err := copyImportPEMs(ctx, p, func(src, dest string) error {
		return runDocker(ctx, append(compose, "cp", src, service+":"+dest)...)
	}); err != nil {
		return err
	}
	if err := runImportCommands(ctx, func(args ...string) error {
		return runDocker(ctx, append(append(compose, "exec", "-T", service), args...)...)
	}); err != nil {
		return err
	}
	if err := runDocker(ctx, append(compose, "restart", service)...); err != nil {
		return err
	}
	if err := waitFirstBoot(ctx, compose, service); err != nil {
		return err
	}
	if err := verifyImportedServerCert(ctx, func(args ...string) ([]byte, error) {
		return dockerOutput(ctx, append(append(compose, "exec", "-T", service), args...)...)
	}); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "imported lab CA and directory certificate; directory restarted")
	return nil
}

func importTLSContainer(ctx context.Context, dir, container string, stdout io.Writer) error {
	p := paths(dir)
	for _, f := range []string{p.CACert, p.DirectoryCert, p.DirectoryKey} {
		if !fileExists(f) {
			return fmt.Errorf("missing %s (run generate first)", f)
		}
	}
	if fileExists(p.CAKey) {
		fmt.Fprintf(stdout, "ca private key stays on host: %s\n", p.CAKey)
	}
	if err := refuseTmpfsData(ctx, container); err != nil {
		return err
	}
	if err := copyImportPEMs(ctx, p, func(src, dest string) error {
		return runDocker(ctx, "cp", src, container+":"+dest)
	}); err != nil {
		return err
	}
	if err := runImportCommands(ctx, func(args ...string) error {
		return runDocker(ctx, append([]string{"exec", container}, args...)...)
	}); err != nil {
		return err
	}
	if err := runDocker(ctx, "restart", container); err != nil {
		return err
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if runDocker(ctx, "exec", container, "test", "-f", "/data/config/container.inf") == nil &&
			runDocker(ctx, "exec", container, "test", "-S", "/data/run/slapd-localhost.socket") == nil {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	if err := verifyImportedServerCert(ctx, func(args ...string) ([]byte, error) {
		return dockerOutput(ctx, append([]string{"exec", container}, args...)...)
	}); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "imported lab CA and directory certificate; directory restarted")
	return nil
}

func copyImportPEMs(ctx context.Context, p material, cp func(src, dest string) error) error {
	_ = ctx
	for _, c := range [][2]string{
		{p.CACert, "/tmp/labldap-ca.crt"},
		{p.DirectoryCert, "/tmp/labldap-server.crt"},
		{p.DirectoryKey, "/tmp/labldap-server.key"},
	} {
		if err := cp(c[0], c[1]); err != nil {
			return err
		}
	}
	return nil
}

func runImportCommands(ctx context.Context, execFn func(args ...string) error) error {
	_ = ctx
	cmds := [][]string{
		{"dsctl", "localhost", "tls", "import-ca", "/tmp/labldap-ca.crt", caName},
		{"dsctl", "localhost", "tls", "import-server-key-cert", "/tmp/labldap-server.crt", "/tmp/labldap-server.key"},
		{"rm", "-f", "/tmp/labldap-ca.crt", "/tmp/labldap-server.crt", "/tmp/labldap-server.key"},
	}
	for _, args := range cmds {
		if err := execFn(args...); err != nil {
			return err
		}
	}
	return nil
}

func verifyImportedServerCert(ctx context.Context, execFn func(args ...string) ([]byte, error)) error {
	_ = ctx
	out, err := execFn("dsctl", "localhost", "tls", "show-server-cert")
	if err != nil {
		return fmt.Errorf("show-server-cert after restart: %w", err)
	}
	if !strings.Contains(string(out), caName) {
		return fmt.Errorf("after restart, server cert is not issued by %s (tmpfs remount or failed NSS reload)", caName)
	}
	return nil
}

func refuseTmpfsData(ctx context.Context, container string) error {
	typ, err := dockerOutput(ctx, "inspect", "-f",
		`{{range .Mounts}}{{if eq .Destination "/data"}}{{.Type}}{{end}}{{end}}`, container)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(typ)) == "tmpfs" {
		return fmt.Errorf("refusing import: %s has a container-local tmpfs /data (restart remounts empty)", container)
	}
	name, err := dockerOutput(ctx, "inspect", "-f",
		`{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}`, container)
	if err != nil {
		return err
	}
	vol := strings.TrimSpace(string(name))
	if vol == "" {
		return nil
	}
	opts, err := dockerOutput(ctx, "volume", "inspect", "-f", `{{index .Options "type"}}`, vol)
	if err != nil {
		return err
	}
	if volumeOptsAreTmpfs(map[string]string{"type": strings.TrimSpace(string(opts))}) {
		return fmt.Errorf("refusing import: volume %s is tmpfs-backed (restart remounts empty); use the persistent overlay", vol)
	}
	return nil
}

func volumeOptsAreTmpfs(opts map[string]string) bool {
	return strings.EqualFold(strings.TrimSpace(opts["type"]), "tmpfs")
}

func runPublish(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "secrets/tls/instance-ca.crt", "host path for the instance CA")
	project := fs.String("project", "labldap", "Compose project name")
	service := fs.String("service", "directory", "directory service name")
	var files multiFlag
	fs.Var(&files, "f", "Compose file (repeatable)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprint(stdout, usageText)
			return 0
		}
		return 2
	}
	if len(files) == 0 {
		files = []string{"deploy/compose/compose.389ds.yaml", "deploy/compose/compose.389ds-ephemeral.yaml"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := publishInstanceCA(ctx, *out, *project, *service, files, stdout); err != nil {
		fmt.Fprintf(stderr, "setuptls publish: %v\n", err)
		return 1
	}
	return 0
}

func publishInstanceCA(ctx context.Context, dest, project, service string, composeFiles []string, stdout io.Writer) error {
	if overwritesLabCA(dest) {
		return fmt.Errorf("refusing to overwrite lab CA %s while %s exists; use --out instance-ca.crt", dest, labCAKeyFor(dest))
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	compose := composeArgs(project, composeFiles)
	if err := waitFirstBoot(ctx, compose, service); err != nil {
		return err
	}
	if err := runDocker(ctx, append(compose, "cp", service+":/data/config/ca.crt", dest)...); err != nil {
		return err
	}
	if err := os.Chmod(dest, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "published instance CA to %s\n", dest)
	return nil
}

func composeArgs(project string, files []string) []string {
	args := []string{"compose", "-p", project}
	for _, f := range files {
		args = append(args, "-f", f)
	}
	return args
}

// Overlay interpolation keys from deploy/compose/compose.yaml. Compose
// interpolation reads the process environment; tests point these at a
// temp secrets dir instead of the repo-default ../../secrets/*.
var composeOverlayEnv = []string{
	"LABLDAP_DIRECTORY_ENVFILE",
	"LABLDAP_DM_PASSWORD_FILE",
	"LABLDAP_SECRETS_DIR",
	"LABLDAP_TLS_CA",
	"LABLDAP_SCENARIO_FILE",
}

func composePassthroughEnv() []string {
	env := append([]string{}, os.Environ()...)
	for _, key := range composeOverlayEnv {
		v, ok := os.LookupEnv(key)
		if !ok {
			continue
		}
		prefix := key + "="
		replaced := false
		for i, kv := range env {
			if strings.HasPrefix(kv, prefix) {
				env[i] = prefix + v
				replaced = true
			}
		}
		if !replaced {
			env = append(env, prefix+v)
		}
	}
	return env
}

func waitFirstBoot(ctx context.Context, compose []string, service string) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(90 * time.Second)
	}
	for time.Now().Before(deadline) {
		err := runDocker(ctx, append(compose, "exec", "-T", service, "test", "-f", "/data/config/container.inf")...)
		if err == nil {
			if err := runDocker(ctx, append(compose, "exec", "-T", service, "test", "-S", "/data/run/slapd-localhost.socket")...); err == nil {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("directory %s did not reach first-boot marker", service)
}

func runDocker(ctx context.Context, args ...string) error {
	_, err := dockerOutput(ctx, args...)
	return err
}

func dockerOutput(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	if len(args) > 0 && args[0] == "compose" {
		cmd.Env = composePassthroughEnv()
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return out, fmt.Errorf("docker %s: %w", strings.Join(args, " "), err)
		}
		return out, fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, msg)
	}
	return out, nil
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	b := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	if err := os.WriteFile(path, b, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func labCAKeyFor(dest string) string {
	if filepath.Base(dest) != "ca.crt" {
		return ""
	}
	return filepath.Join(filepath.Dir(dest), "ca.key")
}

func overwritesLabCA(dest string) bool {
	key := labCAKeyFor(dest)
	return key != "" && fileExists(key)
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
