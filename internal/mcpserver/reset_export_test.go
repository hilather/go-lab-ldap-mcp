package mcpserver

import (
	"net/http"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/reset"
)

func resetExportServices(dir directory.ResetSupport) *app.Services {
	return app.New(app.Deps{
		Users:            newFakeUsers(),
		Groups:           newFakeGroups(),
		Search:           &fakeSearch{},
		Bind:             &fakeBind{},
		Caps:             fakeCaps{caps: directory.Capabilities{EngineVendor: "389 Project"}},
		Marker:           fakeMarker{m: directory.BaselineMarker{AppliedRevision: "aaa"}},
		Schema:           fakeSchema{},
		ExpectedRevision: "aaa",
		ControlRevision:  "bbb",
		PeopleDN:         "ou=people,dc=example,dc=test",
		GroupsDN:         "ou=groups,dc=example,dc=test",
		ResetDir:         dir,
		SoftReset:        true,
		ScenarioName:     "lab",
		ExportMaxBytes:   1 << 20,
		ResetLock:        reset.NewGate(),
	})
}

func resetExportServer(t *testing.T, svc *app.Services) *Server {
	t.Helper()
	s, err := New(Options{
		Registry: testRegistry(t),
		Services: svc,
		Flags:    RegisterFlags{Mutations: true, Password: true, Reset: true, Export: true},
		MaxBody:  1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMCPResetRequiresConfirmRevisionAndScope(t *testing.T) {
	t.Parallel()
	dir := &fakeResetDir{}
	s := resetExportServer(t, resetExportServices(dir))
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())

	writer, _ := connectMCP(t, mux, writeToken, "")
	denied := callTool(t, writer, ToolResetSuffix, ResetSuffixInput{
		Name: "lab", ExpectedRevision: "aaa", Confirm: true,
	})
	if !denied.IsError {
		t.Fatal("write must not reset")
	}

	sess, _ := connectMCP(t, mux, resetToken, "")
	noConfirm := callTool(t, sess, ToolResetSuffix, ResetSuffixInput{
		Name: "lab", ExpectedRevision: "aaa",
	})
	if !noConfirm.IsError || !strings.Contains(toolErrText(noConfirm), "confirm") {
		t.Fatalf("confirm: %s", toolErrText(noConfirm))
	}
	wrong := callTool(t, sess, ToolResetSuffix, ResetSuffixInput{
		Name: "other", ExpectedRevision: "aaa", Confirm: true,
	})
	if !wrong.IsError {
		t.Fatal("wrong name must fail")
	}
	stale := callTool(t, sess, ToolResetSuffix, ResetSuffixInput{
		Name: "lab", ExpectedRevision: "nope", Confirm: true,
	})
	if !stale.IsError {
		t.Fatal("wrong revision must fail")
	}

	ok := callTool(t, sess, ToolResetSuffix, ResetSuffixInput{
		Name: "lab", ExpectedRevision: "aaa", Confirm: true,
	})
	if ok.IsError {
		t.Fatal(toolErrText(ok))
	}
	st := decodeStructured[app.ResetStatus](t, ok)
	if st.State != string(reset.Ready) || st.ExpectedRevision != "aaa" {
		t.Fatalf("status %+v", st)
	}
}

func TestMCPExportRequiresScopeAndHonorsCeiling(t *testing.T) {
	t.Parallel()
	dir := &fakeResetDir{ldif: "dn: dc=example,dc=test\nobjectClass: domain\n\n"}
	s := resetExportServer(t, resetExportServices(dir))
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())

	writer, _ := connectMCP(t, mux, writeToken, "")
	denied := callTool(t, writer, ToolExportLDIF, ExportLDIFInput{})
	if !denied.IsError {
		t.Fatal("write must not export")
	}

	sess, _ := connectMCP(t, mux, exportToken, "")
	ok := callTool(t, sess, ToolExportLDIF, ExportLDIFInput{})
	if ok.IsError {
		t.Fatal(toolErrText(ok))
	}
	out := decodeStructured[ExportLDIFOutput](t, ok)
	if !strings.Contains(out.LDIF, "dc=example,dc=test") || out.Bytes == 0 {
		t.Fatalf("inline %+v", out)
	}

	dir.limit = true
	handoff := callTool(t, sess, ToolExportLDIF, ExportLDIFInput{})
	if handoff.IsError {
		t.Fatal(toolErrText(handoff))
	}
	got := decodeStructured[ExportLDIFOutput](t, handoff)
	if got.Handoff != exportHandoff || got.LDIF != "" {
		t.Fatalf("handoff %+v", got)
	}
}

func TestMCPResetAndExportDestructiveHints(t *testing.T) {
	t.Parallel()
	s := resetExportServer(t, resetExportServices(&fakeResetDir{}))
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())
	sess, _ := connectMCP(t, mux, testToken, "")
	for tool, err := range sess.Tools(t.Context(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		switch tool.Name {
		case ToolResetSuffix:
			if tool.Annotations == nil || tool.Annotations.DestructiveHint == nil || !*tool.Annotations.DestructiveHint {
				t.Fatal("reset must be destructive")
			}
			if tool.Annotations.ReadOnlyHint {
				t.Fatal("reset is not read-only")
			}
		case ToolExportLDIF:
			if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
				t.Fatal("export must be read-only")
			}
			if tool.Annotations.DestructiveHint != nil && *tool.Annotations.DestructiveHint {
				t.Fatal("export is not destructive")
			}
		}
	}
}
