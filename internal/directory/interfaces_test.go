package directory_test

import (
	"context"
	"io"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// stubDirectory proves every T-045 interface is small and mockable without go-ldap.
type stubDirectory struct{}

func (stubDirectory) List(context.Context, directory.UserListQuery) (directory.UserPage, error) {
	return directory.UserPage{}, nil
}
func (stubDirectory) Get(context.Context, directory.UserID) (directory.User, error) {
	return directory.User{}, nil
}
func (stubDirectory) Add(context.Context, directory.UserSpec) (directory.User, error) {
	return directory.User{}, nil
}
func (stubDirectory) Modify(context.Context, directory.UserID, directory.UserPatch) (directory.User, error) {
	return directory.User{}, nil
}
func (stubDirectory) SetEnabled(context.Context, directory.UserID, bool, directory.Revision) (directory.User, error) {
	return directory.User{}, nil
}
func (stubDirectory) Delete(context.Context, directory.UserID, directory.Revision) error {
	return nil
}
func (stubDirectory) SetPassword(context.Context, directory.UserID, observability.Secret, directory.Revision) error {
	return nil
}

type stubGroups struct{}

func (stubGroups) List(context.Context, directory.GroupListQuery) (directory.GroupPage, error) {
	return directory.GroupPage{}, nil
}
func (stubGroups) Get(context.Context, directory.GroupID) (directory.Group, error) {
	return directory.Group{}, nil
}
func (stubGroups) Add(context.Context, directory.GroupSpec) (directory.Group, error) {
	return directory.Group{}, nil
}
func (stubGroups) Delete(context.Context, directory.GroupID, directory.Revision) error {
	return nil
}
func (stubGroups) AddMembers(context.Context, directory.GroupID, []directory.MemberRef, directory.Revision) (directory.MembershipSummary, error) {
	return directory.MembershipSummary{}, nil
}
func (stubGroups) RemoveMembers(context.Context, directory.GroupID, []directory.MemberRef, directory.Revision) (directory.MembershipSummary, error) {
	return directory.MembershipSummary{}, nil
}
func (stubGroups) ReplaceMembers(context.Context, directory.GroupID, []directory.MemberRef, directory.Revision) (directory.MembershipSummary, error) {
	return directory.MembershipSummary{}, nil
}

type stubSearch struct{}

func (stubSearch) Search(context.Context, directory.SearchQuery) (directory.SearchPage, error) {
	return directory.SearchPage{}, nil
}

type stubBind struct{}

func (stubBind) BindTest(context.Context, string, observability.Secret, directory.Transport) (directory.BindTestResult, error) {
	return directory.BindTestResult{Outcome: directory.BindOutcomeInvalidCredentials}, nil
}

type stubSchema struct{}

func (stubSchema) RootDSE(context.Context) (directory.RootDSE, error) {
	return directory.RootDSE{}, nil
}
func (stubSchema) Schema(context.Context) (directory.Schema, error) {
	return directory.Schema{}, nil
}

type stubReset struct{}

func (stubReset) Inventory(context.Context) (directory.ManagedInventory, error) {
	return directory.ManagedInventory{}, nil
}
func (stubReset) Export(context.Context, io.Writer, directory.ExportOptions) error {
	return nil
}

type stubCaps struct{}

func (stubCaps) Capabilities(context.Context) (directory.Capabilities, error) {
	return directory.Capabilities{RequiredOK: true}, nil
}

type stubMarker struct{}

func (stubMarker) ReadMarker(context.Context) (directory.BaselineMarker, error) {
	return directory.BaselineMarker{}, nil
}

var (
	_ directory.UserRepository      = stubDirectory{}
	_ directory.GroupRepository     = stubGroups{}
	_ directory.SearchRepository    = stubSearch{}
	_ directory.BindTester          = stubBind{}
	_ directory.SchemaRepository    = stubSchema{}
	_ directory.ResetSupport        = stubReset{}
	_ directory.CapabilityInspector = stubCaps{}
	_ directory.MarkerReader        = stubMarker{}
)

func TestInterfacesAreMockable(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	var users directory.UserRepository = stubDirectory{}
	if _, err := users.List(ctx, directory.UserListQuery{}); err != nil {
		t.Fatal(err)
	}
	var groups directory.GroupRepository = stubGroups{}
	if _, err := groups.ReplaceMembers(ctx, "staff", nil, ""); err != nil {
		t.Fatal(err)
	}
	var search directory.SearchRepository = stubSearch{}
	if _, err := search.Search(ctx, directory.SearchQuery{Filter: "(uid=a)"}); err != nil {
		t.Fatal(err)
	}
	var caps directory.CapabilityInspector = stubCaps{}
	got, err := caps.Capabilities(ctx)
	if err != nil || !got.RequiredOK {
		t.Fatalf("%+v %v", got, err)
	}
}
