// Pure DIT view-model helpers. No React, fetch, or generated OpenAPI imports so
// node:test can load this file with type stripping.

export type EntryKind = "suffix" | "ou" | "user" | "group" | "domain" | "container" | "entry";

export type TreeAttr = {
  name: string;
  value: string;
};

export type TreeEntryLike = {
  dn: string;
  objectClasses: readonly string[];
  attributes: readonly TreeAttr[];
};

export type FilterableNode = {
  dn: string;
  rdn: string;
};

export function rdnOf(dn: string): string {
  const trimmed = dn.trim();
  const i = indexOfUnescapedComma(trimmed);
  return i === -1 ? trimmed : trimmed.slice(0, i);
}

export function parentDN(dn: string): string {
  const trimmed = dn.trim();
  const i = indexOfUnescapedComma(trimmed);
  return i === -1 ? trimmed : trimmed.slice(i + 1).trim();
}

function indexOfUnescapedComma(dn: string): number {
  for (let i = 0; i < dn.length; i += 1) {
    if (dn[i] !== ",") {
      continue;
    }
    let slashes = 0;
    for (let j = i - 1; j >= 0 && dn[j] === "\\"; j -= 1) {
      slashes += 1;
    }
    if (slashes % 2 === 0) {
      return i;
    }
  }
  return -1;
}

export function entryKind(objectClasses: readonly string[], opts?: { isSuffix?: boolean }): EntryKind {
  if (opts?.isSuffix === true) {
    return "suffix";
  }
  const oc = new Set(objectClasses.map((item) => item.trim().toLowerCase()));
  if (oc.has("inetorgperson") || oc.has("organizationalperson") || oc.has("posixaccount")) {
    return "user";
  }
  if (oc.has("groupofnames") || oc.has("groupofuniquenames") || oc.has("posixgroup")) {
    return "group";
  }
  if (oc.has("domain") || oc.has("dcobject")) {
    return "domain";
  }
  if (oc.has("organizationalunit")) {
    return "ou";
  }
  if (oc.has("container")) {
    return "container";
  }
  return "entry";
}

export function nodeMatchesFilter(node: FilterableNode, q: string): boolean {
  const needle = q.trim().toLowerCase();
  if (needle === "") {
    return true;
  }
  return node.rdn.toLowerCase().includes(needle) || node.dn.toLowerCase().includes(needle);
}

export function shouldShowNode(
  node: FilterableNode,
  filter: string,
  childrenByBase: ReadonlyMap<string, readonly FilterableNode[]>,
): boolean {
  if (nodeMatchesFilter(node, filter)) {
    return true;
  }
  const kids = childrenByBase.get(node.dn) ?? [];
  return kids.some((kid) => shouldShowNode(kid, filter, childrenByBase));
}

export function childDN(rdnOrDn: string, parent: string): string {
  const typed = rdnOrDn.trim();
  if (typed === "") {
    return parent.trim();
  }
  if (indexOfUnescapedComma(typed) !== -1) {
    return typed;
  }
  return `${typed},${parent.trim()}`;
}

export function isSensitiveAttr(name: string): boolean {
  const n = name.trim().toLowerCase();
  return n === "userpassword" || n.includes("password") || n === "aci";
}

export function userIdFromEntry(entry: TreeEntryLike): string | undefined {
  const uid = entry.attributes.find((attr) => attr.name.trim().toLowerCase() === "uid");
  if (uid !== undefined && uid.value.trim() !== "") {
    return uid.value.trim();
  }
  const rdn = rdnOf(entry.dn);
  if (rdn.toLowerCase().startsWith("uid=")) {
    return rdn.slice(4);
  }
  return undefined;
}

export function membershipFromGroupEntry(entry: TreeEntryLike): string[] {
  const out: string[] = [];
  for (const attr of entry.attributes) {
    const name = attr.name.trim().toLowerCase();
    if (name === "member" || name === "uniquemember") {
      const value = attr.value.trim();
      if (value !== "") {
        out.push(value);
      }
    }
  }
  return out;
}

export function writeOnlyPasswordRow(kind: EntryKind): TreeAttr | undefined {
  if (kind !== "user") {
    return undefined;
  }
  return { name: "userPassword", value: "••••••••" };
}

export function isProtectedTreeDN(dn: string, suffixes: readonly string[]): boolean {
  const needle = dn.trim().toLowerCase();
  if (needle === "") {
    return false;
  }
  for (const suffix of suffixes) {
    const base = suffix.trim().toLowerCase();
    if (base === "") {
      continue;
    }
    if (needle === base || needle === `ou=people,${base}` || needle === `ou=groups,${base}`) {
      return true;
    }
  }
  return false;
}

export function displayMembershipLabel(group: { id: string; dn?: string }): string {
  const dn = group.dn?.trim() ?? "";
  if (dn !== "") {
    return rdnOf(dn);
  }
  const id = group.id.trim();
  return id === "" ? "" : `cn=${id}`;
}
