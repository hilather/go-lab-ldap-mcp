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
