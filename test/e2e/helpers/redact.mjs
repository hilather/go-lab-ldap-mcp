import { readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const BINARY = /\.(png|jpe?g|gif|webp|webm|mp4|zip|gz|woff2?)$/i;

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

export async function redactTree(root, secrets) {
  const findings = [];
  for (const file of await walk(root)) {
    if (BINARY.test(file)) {
      continue;
    }
    let text;
    try {
      text = await readFile(file, "utf8");
    } catch {
      continue;
    }
    if (!artifactContainsSecret(text, secrets)) {
      continue;
    }
    await writeFile(file, redactText(text, secrets));
    findings.push(file);
  }
  return findings;
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
