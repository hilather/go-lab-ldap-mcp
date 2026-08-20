package ds389

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
)

type plugScript struct {
	calls   []string
	show    map[string]string
	setErr  error
	fixup   error
	schema  string
	failSet string
}

func (s *plugScript) exec(_ context.Context, _ string, args []string) ([]byte, []byte, error) {
	joined := strings.Join(args, " ")
	s.calls = append(s.calls, joined)
	if s.failSet != "" && strings.Contains(joined, s.failSet) {
		return nil, []byte(s.failSet), s.setErr
	}
	if strings.Contains(joined, "plugin memberof fixup") {
		if s.fixup != nil {
			return nil, []byte(s.fixup.Error()), s.fixup
		}
		return []byte(`{"desc":"ok"}`), nil, nil
	}
	if strings.Contains(joined, "plugin show") {
		for k, body := range s.show {
			if strings.Contains(joined, k) {
				return []byte(body), nil, nil
			}
		}
		return []byte(`{"type":"entry","attrs":{}}`), nil, nil
	}
	if strings.Contains(joined, "schema attributetypes query") {
		if s.schema == "" {
			s.schema = `{"type":"schema","at":{"names":["nsAccountLock"]}}`
		}
		return []byte(s.schema), nil, nil
	}
	return []byte(`{"ok":true}`), nil, nil
}

func memberOfShow(enabled string, scopes ...string) string {
	if len(scopes) == 0 {
		scopes = []string{""}
	}
	quoted := make([]string, len(scopes))
	for i, s := range scopes {
		quoted[i] = `"` + s + `"`
	}
	return `{
  "type":"entry",
  "attrs":{
    "nsslapd-pluginenabled":["` + enabled + `"],
    "memberofattr":["memberOf"],
    "memberofgroupattr":["member"],
    "memberofentryscope":[` + strings.Join(quoted, ",") + `]
  }
}`
}

func referintShow(enabled string) string {
	return `{
  "type":"entry",
  "attrs":{
    "nsslapd-pluginenabled":["` + enabled + `"],
    "referint-membership-attr":["member"]
  }
}`
}

func TestReconcilePluginsApplyReadback(t *testing.T) {
	sc := &plugScript{show: map[string]string{
		cnMemberOf: memberOfShow("on", "dc=example,dc=test"),
		cnReferint: referintShow("on"),
	}}
	eng := Engine{Runner: Runner{Exec: sc.exec}}
	res, err := eng.ReconcilePlugins(t.Context(), bootstrap.PluginRequest{
		PasswordFile: "/secret/dm.pw",
		Instance:     "localhost",
		Suffix:       "dc=example,dc=test",
		Write:        true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Applied) != 3 {
		t.Fatalf("applied = %v", res.Applied)
	}
	joined := strings.Join(sc.calls, "\n")
	if strings.Contains(joined, "sh -c") {
		t.Fatal("sh -c")
	}
	for _, need := range []string{
		"nsslapd-dynamic-plugins=on",
		"plugin memberof enable",
		"--scope dc=example,dc=test",
		"--autoaddoc nsmemberof",
		"plugin memberof fixup",
		"plugin referential-integrity enable",
		"--membership-attr member",
		"--entry-scope dc=example,dc=test",
		"--container-scope dc=example,dc=test",
		"-y",
	} {
		if !strings.Contains(joined, need) {
			t.Fatalf("missing %q in\n%s", need, joined)
		}
	}
}

func TestReconcilePluginsMissingUnknown(t *testing.T) {
	eng := Engine{Runner: Runner{Exec: (&plugScript{}).exec}}
	_, err := eng.ReconcilePlugins(t.Context(), bootstrap.PluginRequest{
		PasswordFile: "/s", Instance: "localhost", Write: true,
		Plugins: []string{"not-a-plugin"},
	})
	if err == nil || !fieldHas(err, "phase.plugins", "plugin_missing") {
		t.Fatalf("%v", err)
	}
	apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.plugins")
}

func TestReconcilePluginsFixupFailed(t *testing.T) {
	sc := &plugScript{
		fixup: errors.New("not fully enabled"),
		show:  map[string]string{cnMemberOf: memberOfShow("on", "dc=example,dc=test")},
	}
	eng := Engine{Runner: Runner{Exec: sc.exec}}
	_, err := eng.ReconcilePlugins(t.Context(), bootstrap.PluginRequest{
		PasswordFile: "/s", Instance: "localhost", Write: true, Suffix: "dc=example,dc=test",
		Plugins: []string{pluginMemberOf},
	})
	if err == nil || !fieldHas(err, "phase.plugins", "fixup_failed") {
		t.Fatalf("%v", err)
	}
}

func TestReconcilePluginsValidateNoWrite(t *testing.T) {
	sc := &plugScript{show: map[string]string{
		cnMemberOf: memberOfShow("on", "dc=example,dc=test"),
		cnReferint: referintShow("on"),
	}}
	eng := Engine{Runner: Runner{Exec: sc.exec}}
	_, err := eng.ReconcilePlugins(t.Context(), bootstrap.PluginRequest{
		PasswordFile: "/s", Instance: "localhost", Write: false, Suffix: "dc=example,dc=test",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range sc.calls {
		if strings.Contains(c, " enable") || strings.Contains(c, " set") || strings.Contains(c, "fixup") || strings.Contains(c, "replace") {
			t.Fatalf("validate wrote: %s", c)
		}
	}
}

func TestReconcilePluginsValidateDisabled(t *testing.T) {
	sc := &plugScript{show: map[string]string{
		cnMemberOf: memberOfShow("off", "dc=example,dc=test"),
	}}
	eng := Engine{Runner: Runner{Exec: sc.exec}}
	_, err := eng.ReconcilePlugins(t.Context(), bootstrap.PluginRequest{
		PasswordFile: "/s", Instance: "localhost", Write: false, Suffix: "dc=example,dc=test",
		Plugins: []string{pluginMemberOf},
	})
	if err == nil || !fieldHas(err, "phase.plugins", "plugin_missing") {
		t.Fatalf("%v", err)
	}
}

func TestReconcilePluginsSetIdempotent(t *testing.T) {
	sc := &plugScript{
		failSet: "plugin memberof set",
		setErr:  errors.New("There is nothing to set in the plugin entry"),
		show: map[string]string{
			cnMemberOf: memberOfShow("on", "dc=example,dc=test"),
			cnReferint: referintShow("on"),
		},
	}
	eng := Engine{Runner: Runner{Exec: sc.exec}}
	_, err := eng.ReconcilePlugins(t.Context(), bootstrap.PluginRequest{
		PasswordFile: "/s", Instance: "localhost", Write: true, Suffix: "dc=example,dc=test",
		Plugins: []string{pluginMemberOf},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestReconcilePluginsAdditionalSuffixScopes(t *testing.T) {
	primary := "dc=example,dc=test"
	extra := "dc=region1,dc=example,dc=net"
	sc := &plugScript{show: map[string]string{
		cnMemberOf: memberOfShow("on", primary, extra),
		cnReferint: referintShow("on"),
	}}
	eng := Engine{Runner: Runner{Exec: sc.exec}}
	_, err := eng.ReconcilePlugins(t.Context(), bootstrap.PluginRequest{
		PasswordFile:       "/s",
		Instance:           "localhost",
		Write:              true,
		Suffix:             primary,
		AdditionalSuffixes: []string{extra},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(sc.calls, "\n")
	for _, need := range []string{
		"--scope " + primary,
		"--scope " + extra,
		"plugin memberof fixup --wait --timeout 60 " + primary,
		"plugin memberof fixup --wait --timeout 60 " + extra,
		"--entry-scope delete",
		"--container-scope delete",
	} {
		if !strings.Contains(joined, need) {
			t.Fatalf("missing %q in\n%s", need, joined)
		}
	}
	if strings.Count(joined, "plugin memberof fixup") != 2 {
		t.Fatalf("want 2 MemberOf fixups:\n%s", joined)
	}
	if strings.Contains(joined, "--entry-scope "+primary) {
		t.Fatalf("referint must not pin the primary when extras exist:\n%s", joined)
	}
}

func TestReconcilePluginsAdditionalMemberOfReadback(t *testing.T) {
	sc := &plugScript{show: map[string]string{
		cnMemberOf: memberOfShow("on", "dc=example,dc=test"),
	}}
	eng := Engine{Runner: Runner{Exec: sc.exec}}
	_, err := eng.ReconcilePlugins(t.Context(), bootstrap.PluginRequest{
		PasswordFile:       "/s",
		Instance:           "localhost",
		Write:              false,
		Suffix:             "dc=example,dc=test",
		AdditionalSuffixes: []string{"dc=region1,dc=example,dc=net"},
		Plugins:            []string{pluginMemberOf},
	})
	if err == nil || !fieldHas(err, "phase.plugins", "plugin_missing") {
		t.Fatalf("missing extra MemberOf scope: %v", err)
	}
}

func TestReconcilePluginsNoSecretOnArgv(t *testing.T) {
	sc := &plugScript{show: map[string]string{
		cnMemberOf: memberOfShow("on", "dc=example,dc=test"),
		cnReferint: referintShow("on"),
	}}
	eng := Engine{Runner: Runner{Exec: sc.exec}}
	_, err := eng.ReconcilePlugins(context.Background(), bootstrap.PluginRequest{
		PasswordFile: "/secret/dm.pw", Instance: "localhost", Write: true, Suffix: "dc=example,dc=test",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range sc.calls {
		if strings.Contains(c, "dm.pw") && !strings.Contains(c, "-y") {
			t.Fatalf("password file used without -y: %s", c)
		}
		if strings.Contains(strings.ToLower(c), "password=") {
			t.Fatalf("secret on argv: %s", c)
		}
	}
}
