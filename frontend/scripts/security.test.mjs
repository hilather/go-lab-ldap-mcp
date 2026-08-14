import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const srcRoot = join(root, "src");

async function walkFiles(dir) {
  const out = [];
  for (const ent of await readdir(dir, { withFileTypes: true })) {
    const p = join(dir, ent.name);
    if (ent.isDirectory()) {
      out.push(...(await walkFiles(p)));
      continue;
    }
    if (/\.(ts|tsx|js|mjs)$/.test(ent.name) && !ent.name.endsWith(".test.ts")) {
      out.push(p);
    }
  }
  return out;
}

test("token and CSRF stay out of Web Storage, IndexedDB, and the URL", async () => {
  const files = await walkFiles(srcRoot);
  assert.ok(files.length > 0, "expected frontend source");
  for (const file of files) {
    const text = await readFile(file, "utf8");
    assert.doesNotMatch(
      text,
      /localStorage|sessionStorage|indexedDB/i,
      `${file} must not touch Web Storage`,
    );
    assert.doesNotMatch(
      text,
      /searchParams\.(set|append)\(\s*['"]token['"]/i,
      `${file} must not put a token in the URL`,
    );
    assert.doesNotMatch(
      text,
      /location\.(hash|search)\s*=/i,
      `${file} must not assign location search/hash`,
    );
  }
});

test("login form posts the token and clears retained field state", async () => {
  const login = await readFile(join(srcRoot, "auth/LoginPage.tsx"), "utf8");
  assert.match(login, /type="password"/);
  assert.match(login, /method="post"/);
  assert.match(login, /clearedLoginValues/);
  assert.match(login, /createSession/);
  assert.match(login, /reason === "expired"/);
  assert.match(login, /isCompleteBrowserSession/);
  assert.match(login, /loginFailureKind/);
  assert.match(login, /role=\{notice\.role\}/);
  assert.match(login, /aria-live="assertive"/);
  assert.doesNotMatch(login, /localStorage|sessionStorage|indexedDB/i);
});

test("session exchange stores CSRF in memory and never the bearer after login", async () => {
  const session = await readFile(join(srcRoot, "api/session.ts"), "utf8");
  assert.match(session, /setMemoryCSRF/);
  assert.match(session, /clearMemoryBearer/);
  assert.match(session, /clearSessionQueryData/);
  assert.doesNotMatch(session, /setMemoryBearer\(/);
  assert.match(session, /return "csrf"/);
  assert.doesNotMatch(
    session,
    /status === 403[\s\S]{0,80}clearBrowserSecrets/,
    "403 CSRF failure must not clear local state as a successful logout",
  );
});

test("logout and expiry invalidate the server session then clear directory data", async () => {
  const query = await readFile(join(srcRoot, "lib/query.ts"), "utf8");
  assert.match(query, /removeQueries\(\s*\{\s*queryKey:\s*directoryQueryKey/);
  const gate = await readFile(join(srcRoot, "auth/SessionGate.tsx"), "utf8");
  assert.match(gate, /deleteSession/);
  assert.match(gate, /endedServerSession/);
  assert.match(gate, /clearSessionClientState/);
  assert.match(gate, /reason: "expired"/);
  const shell = await readFile(join(srcRoot, "shell/AppShell.tsx"), "utf8");
  assert.match(shell, /disabled=\{!canLogout\}/);
  assert.match(shell, /to="\/login"/);
});

test("dashboard covers ready, degraded, outage, and missing scopes", async () => {
  const dash = await readFile(join(srcRoot, "routes/DashboardPage.tsx"), "utf8");
  assert.match(dash, /Directory outage/);
  assert.match(dash, /statusPresentation/);
  assert.match(dash, /Requires scope/);
  assert.match(dash, /Insecure lab configuration/);
  assert.match(dash, /Quick actions/);
  assert.match(dash, /Recent audit/);
  assert.match(dash, /Scenario status/);
  assert.match(dash, /status\.symbol/);
  assert.match(dash, /status\.label/);
});

test("user list and create cover search, sort, empty, and read-only create", async () => {
  const list = await readFile(join(srcRoot, "routes/users/UserListPage.tsx"), "utf8");
  assert.match(list, /emptyListMessage/);
  assert.match(list, /sortUsers/);
  assert.match(list, /aria-sort/);
  assert.match(list, /Create user/);
  assert.match(list, /directory:write|createGate/);

  const create = await readFile(join(srcRoot, "routes/users/UserCreatePage.tsx"), "utf8");
  assert.match(create, /type="password"/);
  assert.match(create, /clearedPasswordFields|setValue\("password", ""\)/);
  assert.match(create, /passwordPolicyHints/);
  assert.match(create, /ALLOWED_USER_ATTRS/);
  assert.match(create, /createUser/);
  assert.match(create, /aria-invalid/);
  assert.match(create, /FormError/);
  const field = await readFile(join(srcRoot, "routes/shared/ResourcePage.tsx"), "utf8");
  assert.match(field, /role="alert"/);
  assert.match(create, /disabled=\{!gate\.ok/);
  assert.doesNotMatch(create, /localStorage|sessionStorage|indexedDB/i);
});

test("user detail mutations send revision and require exact ID delete", async () => {
  const detail = await readFile(join(srcRoot, "routes/users/UserDetailPage.tsx"), "utf8");
  assert.match(detail, /updateUser\(user\.id, patch, user\.revision\)/);
  assert.match(detail, /enableUser\(user\.id, user\.revision\)/);
  assert.match(detail, /disableUser\(user\.id, user\.revision\)/);
  assert.match(detail, /setUserPassword\(user\.id, password, user\.revision\)/);
  assert.match(detail, /deleteUser\(user\.id, user\.revision\)/);
  assert.match(detail, /revisionConflict/);
  assert.match(detail, /ConflictRefresh/);
  assert.match(detail, /ConfirmDelete/);
  assert.match(detail, /resourceId=\{user\.id\}/);
  assert.match(detail, /invalidateUsersAndGroups/);
});

test("group create requires an initial member from bounded server search", async () => {
  const create = await readFile(join(srcRoot, "routes/groups/GroupCreatePage.tsx"), "utf8");
  assert.match(create, /canSubmitGroupCreate/);
  assert.match(create, /MemberSearch/);
  assert.match(create, /emptyGroupExplanation/);
  assert.match(create, /disabled=\{!writeGate\.ok \|\| !memberGate\.ok/);
  const search = await readFile(join(srcRoot, "routes/shared/MemberSearch.tsx"), "utf8");
  assert.match(search, /MEMBER_SEARCH_PAGE_SIZE/);
  assert.match(search, /listUsers/);
  assert.match(search, /listGroups/);
  assert.match(search, /does not\s+run until you submit/);
});

test("group detail has membership summaries, cycle errors, and no attribute PATCH", async () => {
  const detail = await readFile(join(srcRoot, "routes/groups/GroupDetailPage.tsx"), "utf8");
  assert.match(detail, /addGroupMembers/);
  assert.match(detail, /removeGroupMembers/);
  assert.match(detail, /replaceGroupMembers/);
  assert.match(detail, /membershipSummaryLabels/);
  assert.match(detail, /cycleErrorMessage/);
  assert.match(detail, /invalidateUsersAndGroups/);
  assert.match(detail, /no PATCH for groups/);
  assert.doesNotMatch(detail, /api\.PATCH\("\/api\/v1\/groups/);
  assert.match(detail, /deleteGroup\(group\.id, group\.revision\)/);
});
