// Isolated real-engine browser smoke. Secrets and Compose state are temporary;
// the default contract-mock suite never starts Docker.
import { spawn } from "node:child_process";
import { X509Certificate, createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { connect } from "node:tls";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const state = await mkdtemp(join(tmpdir(), "labldap-live-e2e-"));
const storage = process.env.LABLDAP_E2E_LIVE_STORAGE ?? "ephemeral";
if (!["ephemeral", "persistent"].includes(storage)) throw new Error("LABLDAP_E2E_LIVE_STORAGE must be ephemeral or persistent");
const persistent = storage === "persistent";
const project = `labldap-e2e-${process.pid}`;
const port = process.env.LABLDAP_E2E_LIVE_PORT ?? "18443";
const ldapPort = process.env.LABLDAP_E2E_LIVE_LDAP_PORT ?? "13636";
for (const value of [port, ldapPort]) {
  if (!/^\d+$/.test(value) || Number(value) < 1 || Number(value) > 65535) throw new Error("live smoke ports must be 1..65535");
}
const go = process.env.GO ?? "go";
const pnpm = process.env.PNPM ?? "pnpm";

async function run(command, args, options = {}) {
  await new Promise((ok, fail) => {
    const child = spawn(command, args, { cwd: root, stdio: "inherit", ...options });
    child.once("error", fail);
    child.once("exit", (code) => code === 0 ? ok() : fail(new Error(`${command} exited ${code}`)));
  });
}

let env;
let compose;
let started = false;
try {
  await run("ldapsearch", ["-VV"]);
  await run(go, ["run", "./tools/setupsecrets", "--dir", state]);
  // OpenLDAP -y consumes every byte, while service secret readers trim LF.
  const ldapPasswordFile = join(state, "ldap-dm.pw");
  await writeFile(ldapPasswordFile, (await readFile(join(state, "dm.pw"), "utf8")).trim(), { mode: 0o600 });
  const tls = join(state, "tls");
  await run(go, ["run", "./tools/setuptls", "generate", "--dir", tls, "--host", "directory", "--management"]);
  let scenario = await readFile(join(root, "deploy/compose/scenario.yaml"), "utf8");
  scenario = scenario.replace("mode: generated", 'mode: files\n      certFile: /run/secrets/management.crt\n      keyFile: /run/secrets/management.key');
  if (persistent) scenario = scenario.replace("storageMode: ephemeral", "storageMode: persistent");
  const scenarioPath = join(state, "scenario.yaml");
  // Scenario has file references only; the non-root containers must read it.
  await writeFile(scenarioPath, scenario, { mode: 0o644 });
  const overlay = join(state, "browser.yaml");
  await writeFile(overlay, `services:
  directory:
    ports: !override
      - "127.0.0.1:${ldapPort}:3636"
  control:
    ports: !override
      - "127.0.0.1:${port}:8443"
  secret-prep:
    volumes:
      - ${tls}/management.crt:/in/management.crt:ro
      - ${tls}/management.key:/in/management.key:ro
    command:
      - |
        set -eu
        for f in runtime-ldap token-admin user-alice management.crt management.key; do
          cp "/in/$$f" "/out/$$f"
          chown 65532:65532 "/out/$$f"
          chmod 0400 "/out/$$f"
        done
`, { mode: 0o600 });
  env = {
    ...process.env,
    LABLDAP_SECRETS_DIR: state,
    LABLDAP_DM_PASSWORD_FILE: join(state, "dm.pw"),
    LABLDAP_TLS_DIR: tls,
    LABLDAP_TLS_CA: join(tls, "ca.crt"),
    LABLDAP_SCENARIO_FILE: scenarioPath,
  };
  compose = ["compose", "-p", project, "-f", join(root, "deploy/compose/compose.yaml"),
    "-f", join(root, `deploy/compose/compose.${persistent ? "persistent" : "ephemeral"}.yaml`), "-f", overlay];
  started = true;
  await run("docker", [...compose, "up", "-d", "--wait", "control"], { env });

  // Verify the private CA and localhost name before allowing only this leaf's
  // public key through Chromium's test trust exception. Never disable all TLS
  // verification or mutate the user's NSS database.
  const ca = await readFile(join(tls, "ca.crt"));
  await new Promise((ok, fail) => {
    const socket = connect({ host: "127.0.0.1", port: Number(port), servername: "localhost", ca });
    socket.setTimeout(5000, () => socket.destroy(new Error("management TLS verification timed out")));
    socket.once("secureConnect", () => { socket.end(); ok(); });
    socket.once("error", fail);
  });
  const cert = new X509Certificate(await readFile(join(tls, "management.crt")));
  const spki = createHash("sha256").update(cert.publicKey.export({ type: "spki", format: "der" })).digest("base64");
  await run(pnpm, ["install", "--frozen-lockfile"], { cwd: join(root, "test/e2e") });
  await run(pnpm, ["exec", "playwright", "test", "specs/live.spec.ts"], {
    cwd: join(root, "test/e2e"),
    env: {
      ...env,
      LABLDAP_E2E_LIVE: "1",
      LABLDAP_E2E_BASE_URL: `https://localhost:${port}`,
      LABLDAP_E2E_BROWSER_SPKI: spki,
      LABLDAP_E2E_ADMIN_TOKEN: (await readFile(join(state, "token-admin"), "utf8")).trim(),
      LABLDAP_E2E_BIND_PASSWORD: (await readFile(join(state, "user-alice"), "utf8")).trim(),
      LABLDAP_E2E_LDAP_URL: `ldaps://127.0.0.1:${ldapPort}`,
      LABLDAP_E2E_CA_FILE: join(tls, "ca.crt"),
      LABLDAP_E2E_DM_PASSWORD_FILE: ldapPasswordFile,
    },
  });
} finally {
  try {
    if (started) await run("docker", [...compose, "down", "-v", "--remove-orphans"], { env });
  } finally {
    await rm(state, { recursive: true, force: true });
  }
}
