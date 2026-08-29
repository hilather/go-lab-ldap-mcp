import assert from "node:assert/strict";
import { test } from "node:test";
import {
  browserSessionComplete,
  canDestroySession,
  classifyLoginHttpStatus,
  dashboardMode,
  emptyTokenField,
  insecureReasons,
  loginNotice,
  missingScopeReason,
  formatRelativeExpiry,
  navRestriction,
  navigationGroups,
  navigationItems,
  primaryWriteScopeChip,
  quickActions,
  scenarioStatus,
  SCOPE_DIRECTORY_READ,
  SCOPE_DIRECTORY_WRITE,
  sessionEndInvalidated,
  statusPresentation,
} from "./session-model.ts";

test("login notices cover invalid, rate limit, and expired states", () => {
  for (const kind of ["invalid", "rate_limit", "expired"] as const) {
    const notice = loginNotice(kind);
    assert.ok(notice.message.length > 0);
    assert.ok(notice.role === "alert" || notice.role === "status");
  }
  assert.equal(classifyLoginHttpStatus(401), "invalid");
  assert.equal(classifyLoginHttpStatus(429), "rate_limit");
});

test("successful login leaves no retained token field", () => {
  assert.equal(emptyTokenField.token, "");
});

test("dashboard works in ready, degraded, and outage modes", () => {
  assert.equal(
    dashboardMode({ ready: true, directoryUnreachable: false, settled: true }),
    "ready",
  );
  assert.equal(
    dashboardMode({ ready: false, directoryUnreachable: false, settled: true }),
    "degraded",
  );
  assert.equal(
    dashboardMode({ ready: true, directoryUnreachable: true, settled: false }),
    "outage",
  );
  assert.equal(
    dashboardMode({ ready: false, directoryUnreachable: false, settled: false }),
    "loading",
  );
  for (const mode of ["loading", "ready", "degraded", "outage"] as const) {
    const status = statusPresentation(mode);
    assert.ok(status.label.length > 0);
    assert.ok(status.symbol.length > 0);
    assert.ok(status.detail.length > 0);
    assert.notEqual(status.label, status.symbol);
  }
});

test("cookie session without CSRF is not a complete browser session", () => {
  assert.equal(browserSessionComplete(true, false), false);
  assert.equal(browserSessionComplete(true, true), true);
  assert.equal(canDestroySession(false), false);
  assert.equal(canDestroySession(true), true);
  assert.equal(sessionEndInvalidated("deleted"), true);
  assert.equal(sessionEndInvalidated("unauthorized"), true);
  assert.equal(sessionEndInvalidated("csrf"), false);
  assert.equal(sessionEndInvalidated("failed"), false);
});

test("scope-restricted actions name the missing permission", () => {
  const actions = quickActions([SCOPE_DIRECTORY_READ]);
  const create = actions.find((action) => action.id === "create-user");
  assert.ok(create);
  assert.equal(create.enabled, false);
  assert.match(create.reason, /directory:write/);
  assert.equal(missingScopeReason(SCOPE_DIRECTORY_WRITE), "Requires scope directory:write.");
});

test("navigation explains missing scopes without relying on color", () => {
  const users = navigationItems().find((item) => item.href === "/users");
  assert.ok(users);
  assert.equal(navRestriction(users, []), "Requires scope directory:read.");
  assert.equal(navRestriction(users, [SCOPE_DIRECTORY_READ]), "");
});

test("directory nav stays on /tree and bind test is labeled Bind test", () => {
  const items = navigationItems();
  const directory = items.find((item) => item.href === "/tree");
  assert.ok(directory);
  assert.equal(directory.label, "Directory");
  const bind = items.find((item) => item.href === "/auth-test");
  assert.ok(bind);
  assert.equal(bind.label, "Bind test");
  const groups = navigationGroups();
  assert.equal(groups[0]?.items[1]?.label, "Directory");
  const lab = groups.find((group) => group.id === "lab");
  assert.ok(lab);
  assert.equal(lab.label, "Lab");
  assert.deepEqual(
    lab.items.map((item) => item.href),
    ["/schema", "/audit", "/export", "/reset", "/diagnostics"],
  );
});

test("relative expiry is human and never ISO", () => {
  const now = Date.parse("2026-08-29T15:00:00.000Z");
  assert.equal(formatRelativeExpiry("2026-08-29T15:46:00.000Z", now), "expires in 46m");
  assert.equal(formatRelativeExpiry("2026-08-29T17:00:00.000Z", now), "expires in 2h");
  assert.equal(formatRelativeExpiry("2026-09-01T15:00:00.000Z", now), "expires in 3d");
  assert.equal(formatRelativeExpiry("2026-08-29T14:00:00.000Z", now), "expired");
  assert.equal(formatRelativeExpiry("not-a-date", now), "expired");
  assert.doesNotMatch(formatRelativeExpiry("2026-08-29T15:46:00.000Z", now), /T/);
});

test("write-scope chip is a single preferred write scope", () => {
  assert.equal(
    primaryWriteScopeChip(["directory:read", "directory:write", "audit:read"]),
    "directory:write",
  );
  assert.equal(primaryWriteScopeChip(["directory:read", "schema:read"]), undefined);
  assert.equal(primaryWriteScopeChip(["lab:export", "directory:password"]), "directory:password");
});

test("insecurity banner reasons are textual", () => {
  const reasons = insecureReasons({ secureContext: false, transports: ["ldap"] });
  assert.equal(reasons.length, 2);
  for (const reason of reasons) {
    assert.match(reason, /secure|cleartext/i);
  }
});

test("scenario status stays readable during outage and mismatch", () => {
  const outage = scenarioStatus({
    mode: "outage",
    baselineMatch: undefined,
    resetState: undefined,
    markerMatch: undefined,
  });
  assert.match(outage.label, /Unavailable/);
  const mismatch = scenarioStatus({
    mode: "degraded",
    baselineMatch: false,
    resetState: "Ready",
    markerMatch: false,
  });
  assert.match(mismatch.label, /mismatch/i);
});
