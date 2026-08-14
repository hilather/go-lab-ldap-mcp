// Pure user/group view-model helpers. No React, fetch, or generated OpenAPI
// imports so node:test can load this file with type stripping.

export const DEFAULT_LIST_PAGE_SIZE = 25;
export const MEMBER_SEARCH_PAGE_SIZE = 8;
export const PASSWORD_HINT_MIN_LENGTH = 12;

export const ALLOWED_USER_ATTRS = [
  "sn",
  "givenName",
  "mail",
  "displayName",
  "cn",
  "telephoneNumber",
  "title",
  "description",
  "initials",
  "l",
  "st",
  "street",
  "postalCode",
  "ou",
] as const;

const FORBIDDEN_USER_ATTRS = new Set([
  "userpassword",
  "memberof",
  "modifiersname",
  "modifytimestamp",
  "entryuuid",
  "nsuniqueid",
  "createtimestamp",
  "creatorsname",
  "aci",
  "pwdaccountlockedtime",
  "nsaccountlock",
  "entrydn",
  "numsubordinates",
]);

export type UserSortKey = "id" | "uid" | "enabled";
export type SortDir = "asc" | "desc";

export type SortableUser = {
  id: string;
  uid: string;
  enabled: boolean;
};

export type SortableGroup = {
  id: string;
  memberCount: number;
};

export type MemberKind = "user" | "group";

export type MemberChoice = {
  kind: MemberKind;
  id: string;
};

export type AttrRow = {
  name: string;
  value: string;
};

export type CreateGate = {
  ok: boolean;
  reason: string;
};

export function quoteETag(revision: string): string {
  return `"${revision}"`;
}

export function ifMatchHeader(revision: string): { "If-Match": string } {
  return { "If-Match": quoteETag(revision) };
}

export function listQuery(input: { pageSize: number; q: string; cursor: string }): {
  pageSize: number;
  q?: string;
  cursor?: string;
} {
  const query: { pageSize: number; q?: string; cursor?: string } = { pageSize: input.pageSize };
  const q = input.q.trim();
  if (q !== "") {
    query.q = q;
  }
  if (input.cursor !== "") {
    query.cursor = input.cursor;
  }
  return query;
}

export function canSubmitMutation(input: { hasWrite: boolean; csrfPresent: boolean }): CreateGate {
  if (!input.hasWrite) {
    return { ok: false, reason: "Requires scope directory:write." };
  }
  if (!input.csrfPresent) {
    return { ok: false, reason: "Sign in again to restore a CSRF secret before making changes." };
  }
  return { ok: true, reason: "" };
}

export function canSubmitPassword(input: { hasPassword: boolean; csrfPresent: boolean }): CreateGate {
  if (!input.hasPassword) {
    return { ok: false, reason: "Requires scope directory:password." };
  }
  if (!input.csrfPresent) {
    return { ok: false, reason: "Sign in again to restore a CSRF secret before making changes." };
  }
  return { ok: true, reason: "" };
}

export function passwordPolicyHints(scheme: string | undefined): string[] {
  const hints = [
    "The compiled directory password policy is enforced server-side.",
    `Typical lab examples require at least ${String(PASSWORD_HINT_MIN_LENGTH)} characters.`,
    "Passwords never appear on user records or in browser storage.",
  ];
  if (scheme !== undefined && scheme !== "") {
    hints.push(`Storage scheme: ${scheme}.`);
  }
  return hints;
}

export function clearedPasswordFields(): { password: string; confirmPassword: string } {
  return { password: "", confirmPassword: "" };
}

export function passwordsMatch(password: string, confirmPassword: string): boolean {
  return password === confirmPassword;
}

export function isForbiddenUserAttr(name: string): boolean {
  return FORBIDDEN_USER_ATTRS.has(name.trim().toLowerCase());
}

export function isAllowlistedUserAttr(name: string): boolean {
  const canon = name.trim().toLowerCase();
  return ALLOWED_USER_ATTRS.some((item) => item.toLowerCase() === canon);
}

export function attributeRowsFromPairs(pairs: readonly { name: string; value: string }[]): AttrRow[] {
  const rows: AttrRow[] = [];
  for (const pair of pairs) {
    if (isForbiddenUserAttr(pair.name)) {
      continue;
    }
    rows.push({ name: pair.name, value: pair.value });
  }
  return rows;
}

export function attributeMapFromRows(rows: readonly AttrRow[]): Record<string, string> | undefined {
  const attrs: Record<string, string> = {};
  for (const row of rows) {
    const name = row.name.trim();
    if (name === "" || isForbiddenUserAttr(name)) {
      continue;
    }
    attrs[name] = row.value;
  }
  if (Object.keys(attrs).length === 0) {
    return undefined;
  }
  return attrs;
}

// UserPatch is merge-only. Names present on the loaded user but missing from
// the submitted rows must be sent as "" so the server Replace/delete runs.
export function userPatchAttributes(
  current: readonly { name: string; value: string }[],
  rows: readonly AttrRow[],
): Record<string, string> | undefined {
  const attrs = attributeMapFromRows(rows) ?? {};
  const submitted = new Set(Object.keys(attrs).map((name) => name.toLowerCase()));
  for (const pair of current) {
    const name = pair.name.trim();
    if (name === "" || isForbiddenUserAttr(name)) {
      continue;
    }
    if (!submitted.has(name.toLowerCase())) {
      attrs[name] = "";
    }
  }
  if (Object.keys(attrs).length === 0) {
    return undefined;
  }
  return attrs;
}

export function reservedCreateIdMessage(id: string): string | undefined {
  if (id.trim().toLowerCase() === "new") {
    return 'The ID "new" is reserved for the create page.';
  }
  return undefined;
}

export function mappedFormErrors(
  fields: readonly { path: string; message: string }[],
  allowed: readonly string[],
): { name: string; message: string }[] {
  const allow = new Set(allowed);
  const out: { name: string; message: string }[] = [];
  for (const field of fields) {
    const name = formFieldFromProblemPath(field.path);
    if (allow.has(name)) {
      out.push({ name, message: field.message });
    }
  }
  return out;
}

export function firstForbiddenAttr(rows: readonly AttrRow[]): string | undefined {
  for (const row of rows) {
    const name = row.name.trim();
    if (name !== "" && isForbiddenUserAttr(name)) {
      return name;
    }
  }
  return undefined;
}

export type UserSpecInput = {
  id: string;
  uid: string;
  enabled: boolean;
  password: string;
  attributes: readonly AttrRow[];
};

export function toUserSpecBody(input: UserSpecInput): {
  id: string;
  password: string;
  uid?: string;
  enabled?: boolean;
  attributes?: Record<string, string>;
} {
  const spec: {
    id: string;
    password: string;
    uid?: string;
    enabled?: boolean;
    attributes?: Record<string, string>;
  } = { id: input.id.trim(), password: input.password };
  const uid = input.uid.trim();
  if (uid !== "") {
    spec.uid = uid;
  }
  if (!input.enabled) {
    spec.enabled = false;
  }
  const attributes = attributeMapFromRows(input.attributes);
  if (attributes !== undefined) {
    spec.attributes = attributes;
  }
  return spec;
}

export function sortUsers<T extends SortableUser>(items: readonly T[], key: UserSortKey, dir: SortDir): T[] {
  const copy = [...items];
  copy.sort((a, b) => {
    const left = key === "enabled" ? (a.enabled ? "1" : "0") : a[key];
    const right = key === "enabled" ? (b.enabled ? "1" : "0") : b[key];
    const cmp = left.localeCompare(right);
    return dir === "asc" ? cmp : -cmp;
  });
  return copy;
}

export function sortGroups<T extends SortableGroup>(items: readonly T[], key: "id" | "memberCount", dir: SortDir): T[] {
  const copy = [...items];
  copy.sort((a, b) => {
    if (key === "memberCount") {
      const cmp = a.memberCount - b.memberCount;
      return dir === "asc" ? cmp : -cmp;
    }
    const cmp = a.id.localeCompare(b.id);
    return dir === "asc" ? cmp : -cmp;
  });
  return copy;
}

export function nextSortDir(currentKey: string, nextKey: string, currentDir: SortDir): SortDir {
  if (currentKey === nextKey) {
    return currentDir === "asc" ? "desc" : "asc";
  }
  return "asc";
}

export function ariaSort(activeKey: string, key: string, dir: SortDir): "ascending" | "descending" | "none" {
  if (activeKey !== key) {
    return "none";
  }
  return dir === "asc" ? "ascending" : "descending";
}

export function exactIdConfirmed(actual: string, typed: string): boolean {
  return actual !== "" && typed === actual;
}

export function emptyGroupExplanation(): string {
  return "groupOfNames cannot be empty, and LabLDAP does not insert a fake member. Choose at least one existing user or group.";
}

export function canSubmitGroupCreate(members: readonly MemberChoice[]): CreateGate {
  if (!hasValidMember(members)) {
    return { ok: false, reason: emptyGroupExplanation() };
  }
  return { ok: true, reason: "" };
}

export function hasValidMember(members: readonly MemberChoice[]): boolean {
  return members.some((member) => member.id.trim() !== "");
}

export function uniqueMembers(members: readonly MemberChoice[]): MemberChoice[] {
  const seen = new Set<string>();
  const out: MemberChoice[] = [];
  for (const member of members) {
    const id = member.id.trim();
    if (id === "") {
      continue;
    }
    const key = `${member.kind}:${id.toLowerCase()}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push({ kind: member.kind, id });
  }
  return out;
}

export function wouldEmptyGroup(currentCount: number, removingCount: number): boolean {
  return currentCount - removingCount <= 0;
}

export type MembershipBuckets = {
  added: readonly unknown[];
  removed: readonly unknown[];
  unchanged: readonly unknown[];
  rejected: readonly unknown[];
};

export function membershipSummaryLabels(sum: MembershipBuckets): {
  added: number;
  removed: number;
  unchanged: number;
  rejected: number;
} {
  return {
    added: sum.added.length,
    removed: sum.removed.length,
    unchanged: sum.unchanged.length,
    rejected: sum.rejected.length,
  };
}

export function cycleErrorMessage(): string {
  return "That membership would create a cycle. The group was not changed.";
}

export function isCycleField(code: string | undefined, path: string | undefined): boolean {
  return code === "cycle" && (path === undefined || path === "members" || path.startsWith("members."));
}

export function isRevisionConflict(status: number, fields: readonly { path?: string; code?: string }[]): boolean {
  if (status === 412) {
    return true;
  }
  return fields.some(
    (field) =>
      field.code === "conflict" && (field.path === "revision" || field.path === "If-Match"),
  );
}

export function formFieldFromProblemPath(path: string): string {
  if (path === "If-Match" || path === "revision") {
    return "revision";
  }
  if (path === "members" || path.startsWith("members.")) {
    return "members";
  }
  if (path.startsWith("attributes")) {
    return "attributes";
  }
  return path;
}

export function emptyListMessage(kind: "users" | "groups", searching: boolean): string {
  if (searching) {
    return kind === "users" ? "No users match this search." : "No groups match this search.";
  }
  return kind === "users"
    ? "No users are in the directory yet."
    : "No groups are in the directory yet.";
}

export function memberKey(member: MemberChoice): string {
  return `${member.kind}:${member.id}`;
}
