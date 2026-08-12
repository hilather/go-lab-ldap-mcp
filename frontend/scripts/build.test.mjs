import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

test("build writes the placeholder index", async () => {
  await rm(join(root, "dist"), { recursive: true, force: true });
  const result = spawnSync(process.execPath, [join(root, "scripts/build.mjs")], {
    cwd: root,
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  const html = await readFile(join(root, "dist/index.html"), "utf8");
  assert.match(html, /LabLDAP frontend placeholder/);
});
