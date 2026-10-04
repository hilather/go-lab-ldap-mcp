package ldapserver

import (
	"context"
	"strings"
	"sync"
	"testing"
)

// TestModifyChecksEveryChangeBeforeEntryAndAssertion pins resolved CAND-35
// for Modify (contract C8; oracle probes 16 and 18): there is no
// entry-level write check, each change needs write on its own attribute,
// and the checks run in request order before the entry is read and before
// the assertion control, so a caller without write learns neither entry
// existence (50, not 32) nor entry state (50, not 122).
func TestModifyChecksEveryChangeBeforeEntryAndAssertion(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var entryLevel []ACICheck
	opts := writeOptions(t, func(o *Options) {
		o.ACI = &FakeACI{Decide: func(ctx context.Context, tx ReadTx, check ACICheck) (bool, error) {
			if check.Perm == PermWrite && check.Attribute == "" {
				mu.Lock()
				entryLevel = append(entryLevel, check)
				mu.Unlock()
			}
			// Write is denied on description only.
			return !(check.Perm == PermWrite && strings.EqualFold(check.Attribute, "description")), nil
		}}
	})
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	alice := "uid=alice,ou=people,dc=example,dc=test"
	falseAssert := assertionControl(t, &FilterEquality{Attr: "cn", Value: []byte("someone else")}, true)
	desc := ModifyChange{Op: ModifyReplace, Attr: StringAttribute("description", "x")}
	sn := ModifyChange{Op: ModifyReplace, Attr: StringAttribute("sn", "Adams2")}
	op := ModifyChange{Op: ModifyReplace, Attr: StringAttribute("entryUUID", "forged")}
	for _, tc := range []struct {
		name    string
		dn      string
		changes []ModifyChange
		assert  bool
		want    ResultCode
	}{
		{"denied change on a missing entry", "uid=nobody,ou=people,dc=example,dc=test", []ModifyChange{desc}, false, ResultInsufficientAccessRights},
		{"allowed change on a missing entry", "uid=nobody,ou=people,dc=example,dc=test", []ModifyChange{sn}, false, ResultNoSuchObject},
		{"denied change with a false assertion", alice, []ModifyChange{desc}, true, ResultInsufficientAccessRights},
		{"allowed then denied change with a false assertion", alice, []ModifyChange{sn, desc}, true, ResultInsufficientAccessRights},
		{"allowed change with a false assertion", alice, []ModifyChange{sn}, true, ResultAssertionFailed},
		{"operational attribute before a denied change", alice, []ModifyChange{op, desc}, false, ResultConstraintViolation},
		{"denied change before an operational attribute", alice, []ModifyChange{desc, op}, false, ResultInsufficientAccessRights},
	} {
		var ctrls []Control
		if tc.assert {
			ctrls = append(ctrls, falseAssert)
		}
		res := modifyWithControls(t, cl, &ModifyRequest{DN: tc.dn, Changes: tc.changes}, ctrls...)
		if res.Code != tc.want {
			t.Errorf("%s: got %v, want %d", tc.name, res, tc.want)
		}
	}
	e, err := fetchEntry(t, opts, alice)
	if err != nil {
		t.Fatal(err)
	}
	if got := e.Values("sn"); len(got) != 1 || string(got[0]) != "Adams" {
		t.Fatalf("sn = %q: a rejected modify applied a change", got)
	}
	res := modifyWithControls(t, cl, &ModifyRequest{DN: alice, Changes: []ModifyChange{sn}})
	if res.Code != ResultSuccess {
		t.Fatalf("allowed change: %v", res)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(entryLevel) != 0 {
		t.Fatalf("Modify asked entry-level write checks: %+v", entryLevel)
	}
}
