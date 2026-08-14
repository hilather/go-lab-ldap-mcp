import { readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { deflateRawSync, inflateRawSync } from "node:zlib";

const IMAGE = /\.(png|jpe?g|gif|webp)$/i;
const SKIP_REWRITE = /\.(webm|mp4|gz|woff2?)$/i;

// 1x1 PNG used when a screenshot buffer still contains a fixture secret.
const PLACEHOLDER_PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
  "base64",
);

export function redactText(text, secrets) {
  let out = text;
  for (const secret of secrets) {
    if (secret === "") {
      continue;
    }
    out = out.split(secret).join("[redacted]");
  }
  return out;
}

export function artifactContainsSecret(text, secrets) {
  return secrets.some((secret) => secret !== "" && text.includes(secret));
}

export function bufferContainsSecret(buf, secrets) {
  return secrets.some((secret) => secret !== "" && buf.includes(Buffer.from(secret, "utf8")));
}

export async function redactTree(root, secrets) {
  const findings = [];
  for (const file of await walk(root)) {
    if (SKIP_REWRITE.test(file)) {
      continue;
    }
    let buf;
    try {
      buf = await readFile(file);
    } catch {
      continue;
    }
    if (file.endsWith(".zip")) {
      const next = redactZip(buf, secrets);
      if (next !== null && !next.equals(buf)) {
        await writeFile(file, next);
        findings.push(file);
      }
      continue;
    }
    if (IMAGE.test(file)) {
      if (bufferContainsSecret(buf, secrets)) {
        await writeFile(file, PLACEHOLDER_PNG);
        findings.push(file);
      }
      continue;
    }
    const text = buf.toString("utf8");
    if (!artifactContainsSecret(text, secrets)) {
      continue;
    }
    await writeFile(file, redactText(text, secrets));
    findings.push(file);
  }
  return findings;
}

export function redactZip(buf, secrets) {
  const files = readZip(buf);
  if (files === null) {
    return null;
  }
  let changed = false;
  const out = files.map((file) => {
    const next = redactZipMember(file, secrets);
    if (next.data.equals(file.data) === false) {
      changed = true;
    }
    return next;
  });
  return changed ? writeZip(out) : buf;
}

function redactZipMember(file, secrets) {
  if (IMAGE.test(file.name)) {
    if (bufferContainsSecret(file.data, secrets)) {
      return { name: file.name, data: PLACEHOLDER_PNG };
    }
    return file;
  }
  const text = file.data.toString("utf8");
  if (artifactContainsSecret(text, secrets)) {
    return { name: file.name, data: Buffer.from(redactText(text, secrets), "utf8") };
  }
  if (bufferContainsSecret(file.data, secrets)) {
    return { name: file.name, data: Buffer.alloc(0) };
  }
  return file;
}

function readU16(buf, off) {
  return buf.readUInt16LE(off);
}

function readU32(buf, off) {
  return buf.readUInt32LE(off);
}

function readZip(buf) {
  let eocd = -1;
  const min = Math.max(0, buf.length - 22 - 0xffff);
  for (let i = buf.length - 22; i >= min; i -= 1) {
    if (readU32(buf, i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) {
    return null;
  }
  const count = readU16(buf, eocd + 10);
  let p = readU32(buf, eocd + 16);
  const files = [];
  for (let i = 0; i < count; i += 1) {
    if (p + 46 > buf.length || readU32(buf, p) !== 0x02014b50) {
      return null;
    }
    const method = readU16(buf, p + 10);
    const compSize = readU32(buf, p + 20);
    const nameLen = readU16(buf, p + 28);
    const extraLen = readU16(buf, p + 30);
    const commentLen = readU16(buf, p + 32);
    const localOff = readU32(buf, p + 42);
    const name = buf.subarray(p + 46, p + 46 + nameLen).toString("utf8");
    if (localOff + 30 > buf.length || readU32(buf, localOff) !== 0x04034b50) {
      return null;
    }
    const lNameLen = readU16(buf, localOff + 26);
    const lExtraLen = readU16(buf, localOff + 28);
    const dataStart = localOff + 30 + lNameLen + lExtraLen;
    const comp = buf.subarray(dataStart, dataStart + compSize);
    let data;
    try {
      data = method === 0 ? Buffer.from(comp) : method === 8 ? inflateRawSync(comp) : null;
    } catch {
      return null;
    }
    if (data === null) {
      return null;
    }
    files.push({ name, data });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return files;
}

function writeZip(files) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const file of files) {
    const name = Buffer.from(file.name, "utf8");
    const raw = file.data;
    const comp = deflateRawSync(raw);
    const crc = crc32(raw);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(8, 8);
    local.writeUInt16LE(0, 10);
    local.writeUInt16LE(0, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(comp.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt16LE(0, 12);
    central.writeUInt16LE(0, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(comp.length, 20);
    central.writeUInt32LE(raw.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(0, 38);
    central.writeUInt32LE(offset, 42);
    locals.push(Buffer.concat([local, name, comp]));
    centrals.push(Buffer.concat([central, name]));
    offset += 30 + name.length + comp.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);
  return Buffer.concat([...locals, cd, eocd]);
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

async function walk(dir) {
  const out = [];
  let ents;
  try {
    ents = await readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const ent of ents) {
    const p = join(dir, ent.name);
    if (ent.isDirectory()) {
      out.push(...(await walk(p)));
    } else {
      out.push(p);
    }
  }
  return out;
}
