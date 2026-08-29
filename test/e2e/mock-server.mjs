import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL(".", import.meta.url));
const dist = process.env.FRONTEND_DIST ?? join(root, "../../frontend/dist");
const port = Number.parseInt(process.env.LABLDAP_E2E_PORT ?? "4173", 10);
const adminToken = process.env.LABLDAP_E2E_ADMIN_TOKEN ?? "e2e-admin-token";
const readToken = process.env.LABLDAP_E2E_READ_TOKEN ?? "e2e-read-token";
const bindPassword = process.env.LABLDAP_E2E_BIND_PASSWORD ?? "lab-example-password-12";
const scenario = process.env.LABLDAP_E2E_SCENARIO_NAME ?? "example-lab";
const revision =
  process.env.LABLDAP_E2E_REVISION ?? "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

const ALL_SCOPES = [
  "directory:read",
  "directory:write",
  "directory:password",
  "lab:reset",
  "lab:export",
  "schema:read",
  "audit:read",
];

const sessions = new Map();
const audit = [];
let outage = false;
let resetState = { state: "Ready", phase: "Ready", expectedRevision: revision, appliedRevision: revision };
let seq = 1;

function htmlCN() {
  return "<img src=x onerror=alert(1)>Alice";
}

const users = new Map([
  [
    "alice",
    {
      id: "alice",
      uid: "alice",
      dn: "uid=alice,ou=people,dc=example,dc=test",
      enabled: true,
      objectClasses: ["inetOrgPerson"],
      attributes: [
        { name: "cn", value: htmlCN() },
        { name: "uid", value: "alice" },
      ],
      groups: ["staff"],
      revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
  ],
]);

const extraEntries = new Map();

const groups = new Map([
  [
    "staff",
    {
      id: "staff",
      dn: "cn=staff,ou=groups,dc=example,dc=test",
      members: [{ kind: "user", id: "alice" }],
      revision: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    },
  ],
]);

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'",
  });
  res.end(payload);
}

function problem(res, status, title, fields = []) {
  json(res, status, {
    type: "https://labldap.dev/problems/request",
    title,
    status,
    errors: fields,
  });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (raw.trim() === "") {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie ?? "").split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) {
      continue;
    }
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

function sessionOf(req) {
  const id = parseCookies(req).labldap_session;
  if (!id) {
    return undefined;
  }
  return sessions.get(id);
}

function emit(action, actor, target, result) {
  audit.unshift({
    time: new Date().toISOString(),
    action,
    actor,
    target,
    result,
    requestId: `req-${String(seq++)}`,
    revisions: {},
  });
}

function requireSession(req, res, scope) {
  const sess = sessionOf(req);
  if (sess === undefined) {
    problem(res, 401, "authentication required");
    return undefined;
  }
  if (scope !== undefined && !sess.scopes.includes(scope)) {
    problem(res, 403, "insufficient scope", [{ path: "scope", code: "forbidden", message: scope }]);
    return undefined;
  }
  const unsafe = req.method !== "GET" && req.method !== "HEAD" && req.method !== "OPTIONS";
  if (unsafe && req.url !== "/api/v1/session" && req.headers["x-csrf-token"] !== sess.csrf) {
    problem(res, 403, "csrf check failed", [{ path: "csrf", code: "forbidden", message: "csrf token is missing or invalid" }]);
    return undefined;
  }
  return sess;
}

function isDirectChild(dn, base) {
  return typeof dn === "string" && dn.endsWith("," + base) && !dn.slice(0, -(base.length + 1)).includes(",");
}

function hasDirectChildren(base) {
  for (const user of users.values()) {
    if (isDirectChild(user.dn, base)) {
      return true;
    }
  }
  for (const group of groups.values()) {
    if (isDirectChild(group.dn, base)) {
      return true;
    }
  }
  for (const ent of extraEntries.values()) {
    if (isDirectChild(ent.dn, base)) {
      return true;
    }
  }
  return false;
}

function groupToEntry(group) {
  const attributes = [{ name: "cn", value: group.id }];
  for (const member of group.members ?? []) {
    if (member.kind === "user") {
      const user = users.get(member.id);
      attributes.push({
        name: "member",
        value: user?.dn ?? `uid=${member.id},ou=people,dc=example,dc=test`,
      });
    } else {
      const nested = groups.get(member.id);
      attributes.push({
        name: "member",
        value: nested?.dn ?? `cn=${member.id},ou=groups,dc=example,dc=test`,
      });
    }
  }
  return {
    dn: group.dn,
    objectClasses: ["groupOfNames"],
    attributes,
    revision: group.revision,
  };
}

function directoryEntryFor(dn) {
  if (dn === "dc=example,dc=test") {
    return {
      dn,
      objectClasses: ["domain"],
      attributes: [{ name: "dc", value: "example" }],
      revision: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    };
  }
  if (dn === "ou=people,dc=example,dc=test") {
    return {
      dn,
      objectClasses: ["organizationalUnit"],
      attributes: [{ name: "ou", value: "people" }],
      revision: "1111111111111111111111111111111111111111111111111111111111111111",
    };
  }
  if (dn === "ou=groups,dc=example,dc=test") {
    return {
      dn,
      objectClasses: ["organizationalUnit"],
      attributes: [{ name: "ou", value: "groups" }],
      revision: "2222222222222222222222222222222222222222222222222222222222222222",
    };
  }
  for (const user of users.values()) {
    if (user.dn === dn) {
      return {
        dn: user.dn,
        objectClasses: user.objectClasses,
        attributes: user.attributes,
        revision: user.revision,
      };
    }
  }
  for (const group of groups.values()) {
    if (group.dn === dn) {
      return groupToEntry(group);
    }
  }
  return extraEntries.get(dn);
}

function treeNodesFor(base) {
  const nodes = [];
  const seen = new Set();
  const push = (node) => {
    if (seen.has(node.dn)) {
      return;
    }
    seen.add(node.dn);
    nodes.push(node);
  };
  if (base === "dc=example,dc=test") {
    push({
      dn: "ou=people,dc=example,dc=test",
      rdn: "ou=people",
      objectClasses: ["organizationalUnit"],
      hasChildren: false,
    });
    push({
      dn: "ou=groups,dc=example,dc=test",
      rdn: "ou=groups",
      objectClasses: ["organizationalUnit"],
      hasChildren: false,
    });
  }
  for (const user of users.values()) {
    if (isDirectChild(user.dn, base)) {
      push({
        dn: user.dn,
        rdn: user.dn.split(",")[0],
        objectClasses: user.objectClasses,
        hasChildren: hasDirectChildren(user.dn),
        revision: user.revision,
      });
    }
  }
  for (const group of groups.values()) {
    if (isDirectChild(group.dn, base)) {
      push({
        dn: group.dn,
        rdn: group.dn.split(",")[0],
        objectClasses: ["groupOfNames"],
        hasChildren: hasDirectChildren(group.dn),
        revision: group.revision,
      });
    }
  }
  for (const ent of extraEntries.values()) {
    if (isDirectChild(ent.dn, base)) {
      push({
        dn: ent.dn,
        rdn: ent.dn.split(",")[0],
        objectClasses: ent.objectClasses,
        hasChildren: hasDirectChildren(ent.dn),
        revision: ent.revision,
      });
    }
  }
  return nodes;
}

function directoryUnavailable(res) {
  if (!outage) {
    return false;
  }
  problem(res, 503, "directory unavailable");
  return true;
}

async function handleAPI(req, res, url) {
  const path = url.pathname;

  if (req.method === "POST" && path === "/__e2e/outage") {
    const body = await readBody(req);
    outage = body.enabled === true;
    json(res, 200, { enabled: outage });
    return;
  }

  if (req.method === "GET" && path === "/health") {
    json(res, 200, { status: "ok" });
    return;
  }
  if (req.method === "GET" && path === "/health/ready") {
    json(res, outage ? 503 : 200, { status: outage ? "not_ready" : "ready" });
    return;
  }

  if (req.method === "POST" && path === "/api/v1/session") {
    const body = await readBody(req);
    const token = String(body.token ?? "");
    let scopes;
    if (token === adminToken) {
      scopes = ALL_SCOPES;
    } else if (token === readToken) {
      scopes = ["directory:read", "schema:read"];
    } else {
      problem(res, 401, "authentication required");
      return;
    }
    const id = `sess-${String(seq++)}`;
    const csrf = `csrf-${id}`;
    sessions.set(id, { id, scopes, csrf });
    emit("session.create", `session:${id}`, "session", "success");
    res.setHeader("Set-Cookie", `labldap_session=${id}; Path=/; HttpOnly; SameSite=Strict`);
    json(res, 201, { id, csrfToken: csrf, expiresAt: new Date(Date.now() + 8 * 3600_000).toISOString() });
    return;
  }

  if (req.method === "GET" && path === "/api/v1/session") {
    const sess = requireSession(req, res);
    if (sess === undefined) {
      return;
    }
    json(res, 200, {
      id: sess.id,
      scopes: sess.scopes,
      expiresAt: new Date(Date.now() + 8 * 3600_000).toISOString(),
    });
    return;
  }

  if (req.method === "DELETE" && path === "/api/v1/session") {
    const sess = requireSession(req, res);
    if (sess === undefined) {
      return;
    }
    sessions.delete(sess.id);
    res.writeHead(204, { "Cache-Control": "no-store" });
    res.end();
    return;
  }

  if (req.method === "GET" && path === "/api/v1/diagnostics") {
    if (requireSession(req, res) === undefined) {
      return;
    }
    json(res, 200, {
      ready: !outage,
      markerMatch: !outage,
      pool: { active: 0, idle: 1, max: 4 },
      reset: { state: resetState.state },
    });
    return;
  }

  if (req.method === "GET" && path === "/api/v1/capabilities") {
    if (requireSession(req, res, "directory:read") === undefined || directoryUnavailable(res)) {
      return;
    }
    json(res, 200, {
      engineVendor: "389 Directory Server",
      engineVersion: "e2e",
      adapterVersion: "e2e",
      requiredOK: true,
      passwordScheme: "PBKDF2-SHA256",
      transports: ["ldaps"],
      plugins: [],
      controls: [],
    });
    return;
  }

  if (req.method === "GET" && path === "/api/v1/baseline") {
    if (requireSession(req, res, "directory:read") === undefined || directoryUnavailable(res)) {
      return;
    }
    json(res, 200, {
      expectedRevision: revision,
      appliedRevision: revision,
      controlRevision: revision,
      match: true,
    });
    return;
  }

  if (req.method === "GET" && path === "/api/v1/version") {
    if (requireSession(req, res, "directory:read") === undefined) {
      return;
    }
    json(res, 200, { component: "labldap", version: "e2e", revision: "test", time: new Date().toISOString() });
    return;
  }

  if (req.method === "GET" && path === "/api/v1/suffixes") {
    if (requireSession(req, res, "directory:read") === undefined || directoryUnavailable(res)) {
      return;
    }
    json(res, 200, {
      primary: "dc=example,dc=test",
      additional: [],
      all: ["dc=example,dc=test"],
    });
    return;
  }

  if (req.method === "POST" && path === "/api/v1/tree") {
    if (requireSession(req, res, "directory:read") === undefined || directoryUnavailable(res)) {
      return;
    }
    const body = await readBody(req);
    const base = String(body.base ?? "dc=example,dc=test");
    json(res, 200, { base, nodes: treeNodesFor(base) });
    return;
  }

  if (path === "/api/v1/entries") {
    if (req.method === "GET") {
      if (requireSession(req, res, "directory:read") === undefined || directoryUnavailable(res)) {
        return;
      }
      const dn = url.searchParams.get("dn") ?? "";
      const ent = directoryEntryFor(dn);
      if (ent === undefined) {
        problem(res, 404, "not found");
        return;
      }
      json(res, 200, ent);
      return;
    }
    if (req.method === "POST") {
      if (requireSession(req, res, "directory:write") === undefined || directoryUnavailable(res)) {
        return;
      }
      const body = await readBody(req);
      const dn = String(body.dn ?? "");
      const classes = Array.isArray(body.objectClasses) ? body.objectClasses : [];
      const stored = classes.map((c) => (String(c).toLowerCase() === "container" ? "organizationalUnit" : c));
      const ent = {
        dn,
        objectClasses: stored,
        attributes: [],
        revision: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      };
      extraEntries.set(dn, ent);
      json(res, 201, ent);
      return;
    }
    if (req.method === "DELETE") {
      if (requireSession(req, res, "directory:write") === undefined || directoryUnavailable(res)) {
        return;
      }
      if (url.searchParams.get("confirm") !== "true") {
        problem(res, 400, "confirm required", [{ path: "confirm", code: "required", message: "destructive delete requires confirm" }]);
        return;
      }
      extraEntries.delete(url.searchParams.get("dn") ?? "");
      res.writeHead(204, { "Cache-Control": "no-store" });
      res.end();
      return;
    }
  }

  if (req.method === "POST" && path === "/api/v1/entries/move") {
    if (requireSession(req, res, "directory:write") === undefined || directoryUnavailable(res)) {
      return;
    }
    const body = await readBody(req);
    const from = extraEntries.get(String(body.dn ?? ""));
    if (from === undefined) {
      problem(res, 404, "not found");
      return;
    }
    extraEntries.delete(from.dn);
    from.dn = String(body.newDN ?? from.dn);
    extraEntries.set(from.dn, from);
    json(res, 200, from);
    return;
  }

  if (req.method === "POST" && path === "/api/v1/users") {
    if (requireSession(req, res, "directory:write") === undefined || directoryUnavailable(res)) {
      return;
    }
    const body = await readBody(req);
    const id = String(body.id ?? "");
    const user = {
      id,
      uid: body.uid ?? id,
      dn: body.dn ?? `uid=${id},ou=people,dc=example,dc=test`,
      enabled: true,
      objectClasses: ["inetOrgPerson"],
      attributes: [],
      groups: [],
      revision: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    };
    users.set(id, user);
    extraEntries.set(user.dn, {
      dn: user.dn,
      objectClasses: user.objectClasses,
      attributes: [],
      revision: user.revision,
    });
    json(res, 201, user);
    return;
  }

  if (req.method === "GET" && path === "/api/v1/users") {
    if (requireSession(req, res, "directory:read") === undefined || directoryUnavailable(res)) {
      return;
    }
    json(res, 200, { items: [...users.values()] });
    return;
  }

  if (req.method === "GET" && path.startsWith("/api/v1/users/")) {
    if (requireSession(req, res, "directory:read") === undefined || directoryUnavailable(res)) {
      return;
    }
    const id = decodeURIComponent(path.slice("/api/v1/users/".length).split("/")[0] ?? "");
    const user = users.get(id);
    if (user === undefined) {
      problem(res, 404, "not found");
      return;
    }
    if (path.endsWith("/groups")) {
      json(res, 200, { items: user.groups.map((gid) => groups.get(gid)).filter(Boolean) });
      return;
    }
    json(res, 200, user);
    return;
  }

  if (req.method === "GET" && path === "/api/v1/groups") {
    if (requireSession(req, res, "directory:read") === undefined || directoryUnavailable(res)) {
      return;
    }
    json(res, 200, { items: [...groups.values()] });
    return;
  }

  if (req.method === "POST" && path === "/api/v1/search") {
    if (requireSession(req, res, "directory:read") === undefined || directoryUnavailable(res)) {
      return;
    }
    const body = await readBody(req);
    const filter = String(body.filter ?? "");
    if (filter.trim() === "") {
      problem(res, 400, "filter is empty", [{ path: "filter", code: "empty", message: "filter is empty" }]);
      return;
    }
    if (filter.includes("objectClass=*") || filter === "*") {
      problem(res, 400, "search too broad", [{ path: "filter", code: "over_broad", message: "filter is over-broad" }]);
      return;
    }
    const attrs = Array.isArray(body.attributes) ? body.attributes : [];
    if (attrs.some((name) => String(name).toLowerCase() === "userpassword")) {
      problem(res, 400, "forbidden attribute", [{ path: "attributes", code: "forbidden", message: "attribute is forbidden" }]);
      return;
    }
    const entries = [];
    if (filter.includes("alice") || filter.includes("img")) {
      const user = users.get("alice");
      entries.push({ dn: user.dn, attributes: user.attributes });
    }
    json(res, 200, { entries });
    return;
  }

  if (req.method === "POST" && path === "/api/v1/auth-tests") {
    if (requireSession(req, res, "directory:password") === undefined || directoryUnavailable(res)) {
      return;
    }
    const body = await readBody(req);
    const ok = body.identity === "alice" && body.password === bindPassword;
    json(res, 200, { outcome: ok ? "success" : "invalid_credentials" });
    return;
  }

  if (req.method === "GET" && path === "/api/v1/rootdse") {
    if (requireSession(req, res, "schema:read") === undefined || directoryUnavailable(res)) {
      return;
    }
    json(res, 200, {
      namingContexts: ["dc=example,dc=test"],
      vendorName: "389 Directory Server",
      vendorVersion: "e2e",
      supportedControls: [],
      supportedSASL: [],
    });
    return;
  }

  if (req.method === "GET" && path === "/api/v1/schema") {
    if (requireSession(req, res, "schema:read") === undefined || directoryUnavailable(res)) {
      return;
    }
    json(res, 200, {
      objectClasses: [
        { name: "inetOrgPerson", kind: "STRUCTURAL", must: ["cn", "sn"], may: ["mail", "uid"], sup: ["organizationalPerson"] },
        { name: "groupOfNames", kind: "STRUCTURAL", must: ["member"], may: ["description"], sup: ["top"] },
      ],
      attributes: [
        { name: "uid", syntax: "1.3.6.1.4.1.1466.115.121.1.15", singleValue: true },
        { name: "cn", syntax: "1.3.6.1.4.1.1466.115.121.1.15", singleValue: false },
        { name: "mail", syntax: "1.3.6.1.4.1.1466.115.121.1.15", singleValue: false },
      ],
    });
    return;
  }

  if (req.method === "GET" && path === "/api/v1/audit") {
    if (requireSession(req, res, "audit:read") === undefined) {
      return;
    }
    const action = url.searchParams.get("action") ?? "";
    const actor = url.searchParams.get("actor") ?? "";
    const items = audit.filter((ev) => (action === "" || ev.action === action) && (actor === "" || ev.actor.includes(actor)));
    json(res, 200, { items: items.slice(0, 25) });
    return;
  }

  if (path === "/api/v1/reset") {
    if (requireSession(req, res, "lab:reset") === undefined) {
      return;
    }
    if (req.method === "GET") {
      json(res, 200, resetState);
      return;
    }
    if (req.method === "POST") {
      const body = await readBody(req);
      if (body.name !== scenario) {
        problem(res, 400, "scenario confirmation does not match", [
          { path: "name", code: "confirmation", message: "scenario name does not match compiled metadata.name" },
        ]);
        return;
      }
      if (body.expectedRevision !== revision) {
        problem(res, 400, "expected revision does not match", [
          { path: "expectedRevision", code: "conflict", message: "expected revision does not match" },
        ]);
        return;
      }
      resetState = { ...resetState, state: "Resetting", phase: "delete" };
      setTimeout(() => {
        resetState = { ...resetState, state: "Ready", phase: "Ready" };
      }, 200);
      json(res, 202, resetState);
      return;
    }
  }

  if (req.method === "GET" && path === "/api/v1/export") {
    if (requireSession(req, res, "lab:export") === undefined || directoryUnavailable(res)) {
      return;
    }
    res.writeHead(200, {
      "Content-Type": "text/plain; charset=utf-8",
      "Content-Disposition": 'attachment; filename="labldap-export.ldif"',
      "Cache-Control": "no-store",
    });
    res.end("dn: dc=example,dc=test\nobjectClass: domain\n");
    return;
  }

  problem(res, 404, "not found");
}

const types = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".json": "application/json",
  ".woff2": "font/woff2",
};

function serveStatic(req, res, urlPath) {
  const cleaned = normalize(urlPath).replace(/^(\.\.[/\\])+/, "");
  let file = join(dist, cleaned === "/" ? "index.html" : cleaned);
  if (!existsSync(file) || statSync(file).isDirectory()) {
    file = join(dist, "index.html");
  }
  if (!existsSync(file)) {
    res.writeHead(500, { "Content-Type": "text/plain" });
    res.end("frontend dist missing; run make frontend-build");
    return;
  }
  const ctype = types[extname(file)] ?? "application/octet-stream";
  res.writeHead(200, {
    "Content-Type": ctype,
    "Cache-Control": extname(file) === ".html" ? "no-cache" : "public, max-age=31536000, immutable",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'",
  });
  createReadStream(file).pipe(res);
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://127.0.0.1:${String(port)}`);
  try {
    if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/health") || url.pathname.startsWith("/__e2e/")) {
      await handleAPI(req, res, url);
      return;
    }
    serveStatic(req, res, url.pathname);
  } catch (err) {
    problem(res, 500, err instanceof Error ? err.message : "internal error");
  }
});

server.listen(port, "127.0.0.1", () => {
  process.stdout.write(`e2e mock listening on 127.0.0.1:${String(port)}\n`);
});
