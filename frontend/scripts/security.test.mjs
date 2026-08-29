import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const srcRoot = join(root, "src");

async function walkFiles(dir, re = /\.(ts|tsx|js|mjs)$/) {
  const out = [];
  for (const ent of await readdir(dir, { withFileTypes: true })) {
    const p = join(dir, ent.name);
    if (ent.isDirectory()) {
      out.push(...(await walkFiles(p, re)));
      continue;
    }
    if (re.test(ent.name) && !ent.name.endsWith(".test.ts")) {
      out.push(p);
    }
  }
  return out;
}

test("UI never assigns innerHTML and renders LDAP strings as text", async () => {
  const files = await walkFiles(srcRoot);
  for (const file of files) {
    const text = await readFile(file, "utf8");
    assert.doesNotMatch(text, /dangerouslySetInnerHTML/, `${file} must not inject HTML`);
    assert.doesNotMatch(text, /\.innerHTML\s*=/, `${file} must not assign innerHTML`);
  }
  const safe = await readFile(join(srcRoot, "routes/shared/SafeText.tsx"), "utf8");
  assert.match(safe, /asText/);
  assert.match(safe, /aria-live/);
  const search = await readFile(join(srcRoot, "routes/search/SearchPage.tsx"), "utf8");
  assert.match(search, /<SafeText value=\{attr\.value\}/);
  const confirm = await readFile(join(srcRoot, "routes/shared/ConfirmDelete.tsx"), "utf8");
  assert.match(confirm, /aria-labelledby/);
  assert.match(confirm, /firstFocusable/);
  assert.match(confirm, /confirm-dialog/);
  assert.match(confirm, /button-danger/);
  const conflict = await readFile(join(srcRoot, "routes/shared/ConflictRefresh.tsx"), "utf8");
  assert.match(conflict, /firstFocusable/);
});

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
  assert.match(login, /brand-mark/);
  assert.match(login, /button-primary/);
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
  assert.match(shell, /formatRelativeExpiry/);
  assert.doesNotMatch(shell, /Granted scopes/);
  assert.doesNotMatch(shell, /scopes\.map/);
  const nav = await readFile(join(srcRoot, "lib/session-model.ts"), "utf8");
  assert.match(nav, /label: "Directory"/);
});

test("UI does not load remote fonts or use inline style props", async () => {
  const files = [...(await walkFiles(srcRoot, /\.(ts|tsx|js|mjs|css)$/)), join(root, "index.html")];
  for (const file of files) {
    const text = await readFile(file, "utf8");
    assert.doesNotMatch(
      text,
      /fonts\.googleapis\.com|fonts\.gstatic\.com/i,
      `${file} must not load Google Fonts`,
    );
    if (/\.(ts|tsx)$/.test(file)) {
      assert.doesNotMatch(text, /style=\{\{/, `${file} must not use inline style props`);
    }
  }
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
  assert.match(dash, /safeAuditField\(event\.actor\)/);
  assert.match(dash, /safeAuditField\(event\.target\)/);
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
  assert.match(create, /reservedCreateIdMessage/);
  assert.match(create, /mappedFormErrors/);
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
  assert.match(detail, /userPatchAttributes/);
  assert.match(detail, /applyMutation/);
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
  assert.doesNotMatch(search, /<form/);
  assert.match(search, /type="button"/);
});

test("search console submits explicitly and cannot request forbidden attributes", async () => {
  const page = await readFile(join(srcRoot, "routes/search/SearchPage.tsx"), "utf8");
  assert.match(page, /Search does not run while you type/);
  assert.match(page, /searchEntries\(searchBody/);
  assert.match(page, /SEARCH_ALLOWED_ATTRS/);
  assert.match(page, /type="submit"/);
  assert.doesNotMatch(page, /useQuery\(/);
  assert.match(page, /entryToLDIF/);
  const model = await readFile(join(srcRoot, "lib/search-model.ts"), "utf8");
  assert.match(model, /userpassword/);
  assert.match(model, /isForbiddenSearchAttr/);
});

test("bind test clears the password and does not distinguish unknown user", async () => {
  const page = await readFile(join(srcRoot, "routes/auth-test/AuthTestPage.tsx"), "utf8");
  assert.match(page, /type="password"/);
  assert.match(page, /setValue\("password", ""\)/);
  assert.match(page, /bindOutcomePresentation/);
  assert.match(page, /bindRateLimitMessage/);
  assert.match(page, /createAuthTest/);
  const model = await readFile(join(srcRoot, "lib/ops-model.ts"), "utf8");
  assert.match(model, /does not distinguish an unknown identity/);
});

test("schema browser is read-only and keyboard navigable", async () => {
  const page = await readFile(join(srcRoot, "routes/schema/SchemaPage.tsx"), "utf8");
  assert.match(page, /role="listbox"/);
  assert.match(page, /ArrowDown/);
  assert.match(page, /getRootDSE/);
  assert.match(page, /getSchema/);
  assert.doesNotMatch(page, /role="option"[\s\S]{0,200}<button/);
  assert.doesNotMatch(page, /api\.POST|api\.PATCH|api\.DELETE/);
});

test("audit page uses non-secret identifiers and hides secret-looking fields", async () => {
  const page = await readFile(join(srcRoot, "routes/audit/AuditPage.tsx"), "utf8");
  assert.match(page, /safeAuditField/);
  assert.match(page, /AUDIT_RETENTION_NOTICE/);
  assert.match(page, /Copy request ID/);
  assert.match(page, /SCOPE_AUDIT_READ/);
  assert.doesNotMatch(page, /event\.(password|token|cookie|authorization)/i);
});

test("reset requires scope, exact scenario name, and current revision", async () => {
  const page = await readFile(join(srcRoot, "routes/reset/ResetPage.tsx"), "utf8");
  assert.match(page, /canSubmitReset/);
  assert.match(page, /startReset\(\{ name:/);
  assert.match(page, /expectedRevision: revision/);
  assert.match(page, /invalidateAfterReset/);
  assert.match(page, /wasInProgress/);
  assert.match(page, /disabled=\{!gate\.ok \|\| submitting\}/);
  const exp = await readFile(join(srcRoot, "routes/export/ExportPage.tsx"), "utf8");
  assert.match(exp, /downloadExport/);
  assert.match(exp, /omitSecrets/);
  const diag = await readFile(join(srcRoot, "routes/diagnostics/DiagnosticsPage.tsx"), "utf8");
  assert.match(diag, /getDiagnostics/);
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
