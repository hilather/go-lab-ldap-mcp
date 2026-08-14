import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { artifactContainsSecret, redactText, redactTree } from "./redact.mjs";

test("failure artifacts can be scrubbed of tokens and passwords", async () => {
  const secrets = ["e2e-admin-token", "lab-example-password-12"];
  const dirty = "token=e2e-admin-token password=lab-example-password-12";
  assert.equal(artifactContainsSecret(dirty, secrets), true);
  assert.equal(redactText(dirty, secrets), "token=[redacted] password=[redacted]");

  const dir = await mkdtemp(join(tmpdir(), "labldap-e2e-"));
  const file = join(dir, "trace.log");
  await writeFile(file, dirty);
  const findings = await redactTree(dir, secrets);
  assert.deepEqual(findings, [file]);
  assert.equal(await readFile(file, "utf8"), "token=[redacted] password=[redacted]");
});
