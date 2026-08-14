import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { inflateRawSync } from "node:zlib";
import { artifactContainsSecret, redactText, redactTree, redactZip } from "./redact.mjs";

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

test("trace.zip members that record fill() and POST bodies are redacted", async () => {
  const secrets = ["e2e-admin-token", "lab-example-password-12"];
  const events = [
    JSON.stringify({
      type: "before",
      class: "Frame",
      method: "fill",
      params: { selector: "#login-token", value: "e2e-admin-token" },
    }),
    JSON.stringify({
      type: "log",
      message: 'POST /api/v1/auth-tests {"password":"lab-example-password-12"}',
    }),
  ].join("\n");
  const zip = writeStoredZip("0-trace.trace", Buffer.from(events, "utf8"));
  assert.equal(zip.includes(Buffer.from("e2e-admin-token")), true);

  const cleaned = redactZip(zip, secrets);
  assert.ok(cleaned);
  assert.equal(cleaned.includes(Buffer.from("e2e-admin-token")), false);
  assert.equal(cleaned.includes(Buffer.from("lab-example-password-12")), false);
  assert.match(inflateFirstZipMember(cleaned), /\[redacted\]/);

  const dir = await mkdtemp(join(tmpdir(), "labldap-e2e-zip-"));
  const file = join(dir, "trace.zip");
  await writeFile(file, zip);
  const png = join(dir, "test-failed-1.png");
  await writeFile(png, Buffer.concat([Buffer.from("not-a-real-png "), Buffer.from("e2e-admin-token")]));
  const findings = await redactTree(dir, secrets);
  assert.ok(findings.includes(file));
  assert.ok(findings.includes(png));
  const after = await readFile(file);
  assert.equal(after.includes(Buffer.from("e2e-admin-token")), false);
  assert.equal(after.includes(Buffer.from("lab-example-password-12")), false);
  const pngAfter = await readFile(png);
  assert.equal(pngAfter.includes(Buffer.from("e2e-admin-token")), false);
});

function inflateFirstZipMember(buf) {
  const nameLen = buf.readUInt16LE(26);
  const extraLen = buf.readUInt16LE(28);
  const compSize = buf.readUInt32LE(18);
  const start = 30 + nameLen + extraLen;
  return inflateRawSync(buf.subarray(start, start + compSize)).toString("utf8");
}

function writeStoredZip(name, data) {
  // Stored (method 0) zip so the test does not depend on our writer.
  const n = Buffer.from(name, "utf8");
  const crc = crc32(data);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0, 8);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(data.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(n.length, 26);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt32LE(crc, 16);
  central.writeUInt32LE(data.length, 20);
  central.writeUInt32LE(data.length, 24);
  central.writeUInt16LE(n.length, 28);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(46 + n.length, 12);
  eocd.writeUInt32LE(30 + n.length + data.length, 16);
  return Buffer.concat([local, n, data, central, n, eocd]);
}

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) {
    c ^= buf[i] ?? 0;
    for (let bit = 0; bit < 8; bit += 1) {
      const mask = -(c & 1);
      c = (c >>> 1) ^ (0xedb88320 & mask);
    }
  }
  return (c ^ 0xffffffff) >>> 0;
}
