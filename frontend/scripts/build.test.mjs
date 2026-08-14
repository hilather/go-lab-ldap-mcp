import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readdir, readFile, rm } from "node:fs/promises";
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

test("source never persists bearer tokens in Web Storage", async () => {
  const files = await walkFiles(srcRoot);
  assert.ok(files.length > 0, "expected frontend source");
  for (const file of files) {
    const text = await readFile(file, "utf8");
    assert.doesNotMatch(
      text,
      /localStorage|sessionStorage|indexedDB/i,
      `${file} must not touch Web Storage`,
    );
  }
});

test("client uses generated OpenAPI types, not handwritten User/Group models", async () => {
  const client = await readFile(join(srcRoot, "api/client.ts"), "utf8");
  assert.match(client, /openapi-fetch/);
  assert.match(client, /@labldap\/openapi/);

  const types = await readFile(join(srcRoot, "api/types.ts"), "utf8");
  assert.match(types, /@labldap\/openapi/);
  assert.match(types, /components\["schemas"\]\["User"\]/);
  assert.match(types, /components\["schemas"\]\["Group"\]/);

  const files = await walkFiles(srcRoot);
  const banned = /(?:export\s+)?(?:interface|type)\s+(?:User|Group|SessionView)\s*[=\{]/;
  for (const file of files) {
    if (file.endsWith("api/types.ts")) {
      continue;
    }
    const text = await readFile(file, "utf8");
    assert.doesNotMatch(text, banned, `${file} duplicates a generated resource model`);
  }
});

test("production build emits hashed assets from the lockfile toolchain", async () => {
  await rm(join(root, "dist"), { recursive: true, force: true });
  const result = spawnSync("pnpm", ["build"], {
    cwd: root,
    encoding: "utf8",
    env: process.env,
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);

  const html = await readFile(join(root, "dist/index.html"), "utf8");
  assert.doesNotMatch(html, /LabLDAP frontend placeholder/);
  assert.match(html, /assets\/[^"']+-[A-Za-z0-9_-]{8,}\.[A-Za-z0-9]+/);
  assert.doesNotMatch(html, /<script(?![^>]*src=)/i);

  const assets = await readdir(join(root, "dist/assets"));
  const hashed = assets.filter((name) => /-[A-Za-z0-9_-]{8,}\.[A-Za-z0-9]+$/.test(name));
  assert.ok(hashed.length > 0, `expected hashed files in dist/assets, got ${assets.join(",")}`);
});
