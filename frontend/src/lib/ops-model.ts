// Pure bind-test, schema, audit, reset, and export helpers. No React or
// generated OpenAPI imports so node:test can load this file with type stripping.

export type CreateGate = {
  ok: boolean;
  reason: string;
};

export const BIND_TRANSPORTS = ["ldaps", "starttls", "ldap"] as const;
export type BindTransport = (typeof BIND_TRANSPORTS)[number];

export function canSubmitBindTest(input: { hasPassword: boolean; csrfPresent: boolean }): CreateGate {
  if (!input.hasPassword) {
    return { ok: false, reason: "Requires scope directory:password." };
  }
  if (!input.csrfPresent) {
    return { ok: false, reason: "Sign in again to restore a CSRF secret before testing a bind." };
  }
  return { ok: true, reason: "" };
}

export function clearedBindPassword(): { password: string } {
  return { password: "" };
}

export function bindOutcomePresentation(outcome: string): { title: string; detail: string } {
  switch (outcome) {
    case "success":
      return { title: "Success", detail: "The bind completed." };
    case "invalid_credentials":
      return {
        title: "Not accepted",
        detail:
          "The credentials were not accepted. This result does not distinguish an unknown identity from a wrong password.",
      };
    case "locked":
      return { title: "Locked", detail: "The account is locked." };
    case "disabled":
      return { title: "Disabled", detail: "The account is disabled." };
    case "unavailable":
      return { title: "Unavailable", detail: "The directory could not complete the bind test." };
    default:
      return { title: "Completed", detail: "The bind test finished." };
  }
}

export function bindRateLimitMessage(): string {
  return "Too many bind tests. Wait a minute and try again.";
}

export function filterNamed<T extends { name: string }>(items: readonly T[], q: string): T[] {
  const needle = q.trim().toLowerCase();
  if (needle === "") {
    return [...items];
  }
  return items.filter((item) => item.name.toLowerCase().includes(needle));
}

export function moveIndex(current: number, delta: number, length: number): number {
  if (length <= 0) {
    return -1;
  }
  if (current < 0) {
    return delta >= 0 ? 0 : length - 1;
  }
  const next = current + delta;
  if (next < 0) {
    return 0;
  }
  if (next >= length) {
    return length - 1;
  }
  return next;
}

export const AUDIT_ACTIONS = [
  "authenticate",
  "session.create",
  "session.destroy",
  "user.create",
  "user.update",
  "user.delete",
  "user.set_enabled",
  "user.set_password",
  "group.create",
  "group.delete",
  "group.members",
  "group.add_members",
  "group.remove_members",
  "group.replace_members",
  "bind_test",
  "reset",
  "export",
  "authz.deny",
] as const;

export const DEFAULT_AUDIT_PAGE_SIZE = 25;

export const AUDIT_RETENTION_NOTICE =
  "The in-memory audit ring is process-local. Events are discarded on restart and are not a durable log.";

const SECRETISH = /password|passwd|userpassword|authorization|bearer\s|cookie=|set-cookie|csrf|token=/i;
const JWTISH = /^eyj[a-z0-9_-]+\.[a-z0-9_-]+/i;

export function looksSecret(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed === "") {
    return false;
  }
  if (JWTISH.test(trimmed)) {
    return true;
  }
  if (SECRETISH.test(trimmed) && trimmed.length > 16) {
    return true;
  }
  if (/^(bearer|basic)\s+\S+/i.test(trimmed)) {
    return true;
  }
  return false;
}

export function safeAuditField(value: string): string {
  return looksSecret(value) ? "[redacted]" : value;
}

export function auditQuery(input: { pageSize: number; action: string; actor: string; cursor: string }): {
  pageSize: number;
  action?: string;
  actor?: string;
  cursor?: string;
} {
  const query: { pageSize: number; action?: string; actor?: string; cursor?: string } = {
    pageSize: input.pageSize,
  };
  const action = input.action.trim();
  if (action !== "") {
    query.action = action;
  }
  const actor = input.actor.trim();
  if (actor !== "") {
    query.actor = actor;
  }
  if (input.cursor !== "") {
    query.cursor = input.cursor;
  }
  return query;
}

export function canSubmitReset(input: {
  hasReset: boolean;
  csrfPresent: boolean;
  name: string;
  revision: string;
  currentRevision: string;
  inProgress: boolean;
}): CreateGate {
  if (!input.hasReset) {
    return { ok: false, reason: "Requires scope lab:reset." };
  }
  if (!input.csrfPresent) {
    return { ok: false, reason: "Sign in again to restore a CSRF secret before starting a reset." };
  }
  if (input.inProgress) {
    return { ok: false, reason: "A reset is already in progress." };
  }
  if (input.name.trim() === "") {
    return { ok: false, reason: "Type the exact compiled scenario name." };
  }
  if (input.revision.trim() === "") {
    return { ok: false, reason: "Type the current compiled revision to confirm." };
  }
  if (input.currentRevision !== "" && input.revision !== input.currentRevision) {
    return { ok: false, reason: "Typed revision must match the current compiled revision." };
  }
  return { ok: true, reason: "" };
}

export function isResetInProgress(state: string | undefined): boolean {
  return state === "PreparingReset" || state === "Resetting" || state === "Verifying";
}

export function resetPollInterval(state: string | undefined): number | false {
  return isResetInProgress(state) ? 1000 : false;
}

export function canSubmitExport(input: { hasExport: boolean }): CreateGate {
  if (!input.hasExport) {
    return { ok: false, reason: "Requires scope lab:export." };
  }
  return { ok: true, reason: "" };
}

export function exportConfirmNeeded(omitSecrets: boolean): boolean {
  return !omitSecrets;
}

export function schemaSearchEmpty(kind: "object classes" | "attributes", searching: boolean): string {
  if (searching) {
    return `No ${kind} match this search.`;
  }
  return `No ${kind} were returned.`;
}
