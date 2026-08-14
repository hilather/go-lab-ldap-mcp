// Pure search-console helpers. No React or generated OpenAPI imports so
// node:test can load this file with type stripping.

export const DEFAULT_SEARCH_PAGE_SIZE = 50;
export const SEARCH_SCOPES = ["base", "one", "sub", "children"] as const;
export type SearchScope = (typeof SEARCH_SCOPES)[number];

// Server default allowlist minus skipReturnedAttr / secret names.
export const SEARCH_ALLOWED_ATTRS = [
  "objectClass",
  "uid",
  "cn",
  "sn",
  "givenName",
  "mail",
  "displayName",
  "description",
  "member",
  "uniqueMember",
  "memberOf",
  "ou",
  "dc",
  "nsAccountLock",
  "isMemberOf",
] as const;

const FORBIDDEN_SEARCH_ATTRS = new Set([
  "userpassword",
  "aci",
  "nsslapd-rootpw",
  "nsslapd-rootpwstoragescheme",
  "nsmultiplexorbindcred",
  "nsmultiplexorcredentials",
  "nsds5replicacredentials",
  "entrycsn",
  "modifytimestamp",
  "entryuuid",
  "nsuniqueid",
  "createtimestamp",
  "creatorsname",
  "modifiersname",
  "entrydn",
  "numsubordinates",
  "*",
]);

export type SearchFormValues = {
  base: string;
  scope: SearchScope;
  filter: string;
  pageSize: number;
  attributes: readonly string[];
};

export type SearchAttrChoice = {
  sent: string[];
  blocked: string[];
};

export function isForbiddenSearchAttr(name: string): boolean {
  const canon = name.trim().toLowerCase();
  return canon !== "" && FORBIDDEN_SEARCH_ATTRS.has(canon);
}

export function isAllowlistedSearchAttr(name: string): boolean {
  const canon = name.trim().toLowerCase();
  return SEARCH_ALLOWED_ATTRS.some((item) => item.toLowerCase() === canon);
}

export function requestedSearchAttributes(selected: readonly string[]): SearchAttrChoice {
  const sent: string[] = [];
  const blocked: string[] = [];
  const seen = new Set<string>();
  for (const raw of selected) {
    const name = raw.trim();
    if (name === "") {
      continue;
    }
    const key = name.toLowerCase();
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    if (isForbiddenSearchAttr(name) || !isAllowlistedSearchAttr(name)) {
      blocked.push(name);
      continue;
    }
    sent.push(name);
  }
  return { sent, blocked };
}

export function emptySearchForm(): SearchFormValues {
  return {
    base: "",
    scope: "sub",
    filter: "",
    pageSize: DEFAULT_SEARCH_PAGE_SIZE,
    attributes: [],
  };
}

export function searchBody(input: SearchFormValues, cursor: string): {
  base?: string;
  scope?: SearchScope;
  filter: string;
  attributes?: string[];
  pageSize?: number;
  cursor?: string;
} {
  const attrs = requestedSearchAttributes(input.attributes);
  const body: {
    base?: string;
    scope?: SearchScope;
    filter: string;
    attributes?: string[];
    pageSize?: number;
    cursor?: string;
  } = { filter: input.filter };
  const base = input.base.trim();
  if (base !== "") {
    body.base = base;
  }
  if (input.scope !== "sub") {
    body.scope = input.scope;
  }
  if (attrs.sent.length > 0) {
    body.attributes = attrs.sent;
  }
  if (input.pageSize > 0) {
    body.pageSize = input.pageSize;
  }
  if (cursor !== "") {
    body.cursor = cursor;
  }
  return body;
}

export function searchFieldError(path: string | undefined, code: string | undefined, message: string): string {
  switch (code) {
    case "empty":
      return "Enter an LDAP filter. Search does not run until you submit.";
    case "too_long":
      return "Filter exceeds the configured length limit.";
    case "too_deep":
      return "Filter exceeds the configured nesting depth.";
    case "unbalanced":
      return "Filter parentheses are unbalanced.";
    case "over_broad":
      return "That filter is too broad for a suffix subtree search.";
    case "invalid":
      return path === "cursor" ? "The next-page cursor is invalid. Submit the search again." : "Filter syntax is invalid.";
    case "invalid_dn":
      return "Search base is not a valid DN.";
    case "forbidden":
      return "Search base is outside the managed suffix.";
    case "too_large":
      return "Page size exceeds the configured maximum.";
    default:
      return message;
  }
}

export function searchProblemMessage(fields: readonly { path: string; code?: string; message: string }[], fallback: string): {
  field: "base" | "filter" | "pageSize" | "cursor" | "attributes" | "form";
  message: string;
} {
  for (const field of fields) {
    const message = searchFieldError(field.path, field.code, field.message);
    if (field.path === "base") {
      return { field: "base", message };
    }
    if (field.path === "filter") {
      return { field: "filter", message };
    }
    if (field.path === "pageSize") {
      return { field: "pageSize", message };
    }
    if (field.path === "cursor") {
      return { field: "cursor", message };
    }
    if (field.path === "attributes" || field.path.startsWith("attributes.")) {
      return { field: "attributes", message };
    }
  }
  return { field: "form", message: fallback };
}

export type SearchAttr = { name: string; value: string };

export type SearchEntryView = {
  dn: string;
  attributes: readonly SearchAttr[];
};

export function redactedAttrNames(requested: readonly string[], returned: readonly SearchAttr[]): string[] {
  const present = new Set(returned.map((attr) => attr.name.toLowerCase()));
  const missing: string[] = [];
  for (const name of requested) {
    if (!present.has(name.toLowerCase())) {
      missing.push(name);
    }
  }
  return missing;
}

export function entryToLDIF(entry: SearchEntryView): string {
  const lines = [`dn: ${sanitizeLDIFValue(entry.dn)}`];
  for (const attr of entry.attributes) {
    if (isForbiddenSearchAttr(attr.name)) {
      continue;
    }
    lines.push(`${attr.name}: ${sanitizeLDIFValue(attr.value)}`);
  }
  return `${lines.join("\n")}\n`;
}

function sanitizeLDIFValue(value: string): string {
  return value.replace(/\r?\n/g, " ");
}

export function toggleAttr(selected: readonly string[], name: string): string[] {
  if (isForbiddenSearchAttr(name) || !isAllowlistedSearchAttr(name)) {
    return [...selected];
  }
  if (selected.some((item) => item.toLowerCase() === name.toLowerCase())) {
    return selected.filter((item) => item.toLowerCase() !== name.toLowerCase());
  }
  return [...selected, name];
}

export function validSearchScope(value: string): SearchScope {
  for (const scope of SEARCH_SCOPES) {
    if (scope === value) {
      return scope;
    }
  }
  return "sub";
}
