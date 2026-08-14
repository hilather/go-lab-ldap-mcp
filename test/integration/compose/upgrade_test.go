//go:build integration

package compose

import (
	"net/http"
	"testing"
	"time"
)

// TestPersistentUpgradeRecreateKeepsRuntimeEntry is the T-120 persistent
// volume upgrade stand-in: recreate control on the same named volume
// (first release has no prior image tag). Runtime entries must survive.
func TestPersistentUpgradeRecreateKeepsRuntimeEntry(t *testing.T) {
	root := requireCompose(t)
	proj := composeProject(t, "upg")
	dir := t.TempDir()
	env := writeLabMaterial(t, root, dir)
	t.Cleanup(func() { compose(t, root, proj, env, true, "down", "--remove-orphans", "-v") })
	upStack(t, root, proj, env, true)
	createRuntimeUser(t, root, proj, env)
	if !userExists(t, root, proj, env, "runtime-extra") {
		t.Fatal("expected runtime-extra before recreate")
	}
	compose(t, root, proj, env, true, "up", "-d", "--no-deps", "--force-recreate", "control")
	waitControl(t, root, proj, env, true)
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		if userExists(t, root, proj, env, "runtime-extra") && userExists(t, root, proj, env, "alice") {
			res := hostJSON(t, root, proj, env, http.MethodGet, "/health/ready", nil)
			if res.status == http.StatusOK {
				return
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatal("persistent control recreate must keep runtime-extra and alice")
}
