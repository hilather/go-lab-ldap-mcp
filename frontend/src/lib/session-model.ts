// Pure view-model helpers. No React, fetch, or generated OpenAPI imports so
// node:test can load this file with type stripping.

export const SCOPE_DIRECTORY_READ = "directory:read";
export const SCOPE_DIRECTORY_WRITE = "directory:write";
export const SCOPE_DIRECTORY_PASSWORD = "directory:password";
export const SCOPE_LAB_RESET = "lab:reset";
export const SCOPE_LAB_EXPORT = "lab:export";
export const SCOPE_SCHEMA_READ = "schema:read";
export const SCOPE_AUDIT_READ = "audit:read";

export type LoginNoticeKind = "invalid" | "rate_limit" | "expired" | "reauth" | "unknown";

export type LoginNotice = {
  kind: LoginNoticeKind;
  role: "alert" | "status";
  message: string;
};

export function loginNotice(kind: LoginNoticeKind): LoginNotice {
  switch (kind) {
    case "invalid":
      return {
        kind,
        role: "alert",
        message: "The token was not accepted. Check the value and try again.",
      };
    case "rate_limit":
      return {
        kind,
        role: "alert",
        message: "Too many sign-in attempts. Wait a minute and try again.",
      };
    case "expired":
      return {
        kind,
        role: "status",
        message: "Your session expired. Sign in again to continue.",
      };
    case "reauth":
      return {
        kind,
        role: "status",
        message:
          "This tab has a directory cookie but no CSRF secret. Enter the token again to restore a signed-in session.",
      };
    case "unknown":
      return {
        kind,
        role: "alert",
        message: "Sign-in failed. Try again, or check that the control plane is reachable.",
      };
  }
}

export function classifyLoginHttpStatus(status: number): LoginNoticeKind {
  if (status === 429) {
    return "rate_limit";
  }
  if (status === 401) {
    return "invalid";
  }
  return "unknown";
}

export type DashboardMode = "loading" | "ready" | "degraded" | "outage";

export function dashboardMode(input: {
  ready: boolean | undefined;
  directoryUnreachable: boolean;
  settled: boolean;
}): DashboardMode {
  if (input.directoryUnreachable) {
    return "outage";
  }
  if (!input.settled) {
    return "loading";
  }
  if (input.ready === true) {
    return "ready";
  }
  return "degraded";
}

export type StatusPresentation = {
  mode: DashboardMode;
  symbol: string;
  label: string;
  detail: string;
};

export function statusPresentation(mode: DashboardMode): StatusPresentation {
  switch (mode) {
    case "loading":
      return {
        mode,
        symbol: "…",
        label: "Checking",
        detail: "Waiting for directory readiness.",
      };
    case "ready":
      return {
        mode,
        symbol: "●",
        label: "Ready",
        detail: "The directory is ready for operator workflows.",
      };
    case "degraded":
      return {
        mode,
        symbol: "▲",
        label: "Degraded",
        detail: "The control plane is live, but the directory is not ready.",
      };
    case "outage":
      return {
        mode,
        symbol: "■",
        label: "Outage",
        detail: "The control plane cannot complete directory operations.",
      };
  }
}

export type QuickAction = {
  id: string;
  href: string;
  label: string;
  requiredScope?: string;
  enabled: boolean;
  reason: string;
};

export function hasScope(scopes: readonly string[], required: string): boolean {
  return scopes.includes(required);
}

export function missingScopeReason(required: string): string {
  return `Requires scope ${required}.`;
}

const ACTION_DEFS: readonly {
  id: string;
  href: string;
  label: string;
  requiredScope?: string;
}[] = [
  { id: "users", href: "/users", label: "Users", requiredScope: SCOPE_DIRECTORY_READ },
  { id: "create-user", href: "/users/new", label: "Create user", requiredScope: SCOPE_DIRECTORY_WRITE },
  { id: "groups", href: "/groups", label: "Groups", requiredScope: SCOPE_DIRECTORY_READ },
  { id: "search", href: "/search", label: "Search", requiredScope: SCOPE_DIRECTORY_READ },
  { id: "auth-test", href: "/auth-test", label: "Bind test", requiredScope: SCOPE_DIRECTORY_PASSWORD },
  { id: "schema", href: "/schema", label: "Schema", requiredScope: SCOPE_SCHEMA_READ },
  { id: "audit", href: "/audit", label: "Audit", requiredScope: SCOPE_AUDIT_READ },
  { id: "reset", href: "/reset", label: "Soft reset", requiredScope: SCOPE_LAB_RESET },
  { id: "export", href: "/export", label: "Export", requiredScope: SCOPE_LAB_EXPORT },
  { id: "diagnostics", href: "/diagnostics", label: "Diagnostics" },
];

export function quickActions(scopes: readonly string[]): QuickAction[] {
  return ACTION_DEFS.map((def) => {
    const required = def.requiredScope;
    if (required !== undefined && !hasScope(scopes, required)) {
      return {
        id: def.id,
        href: def.href,
        label: def.label,
        requiredScope: required,
        enabled: false,
        reason: missingScopeReason(required),
      };
    }
    const enabled: QuickAction = {
      id: def.id,
      href: def.href,
      label: def.label,
      enabled: true,
      reason: "",
    };
    if (required !== undefined) {
      enabled.requiredScope = required;
    }
    return enabled;
  });
}

export type NavItem = {
  href: string;
  label: string;
  requiredScope?: string;
};

export function navigationItems(): NavItem[] {
  return [
    { href: "/", label: "Dashboard" },
    { href: "/users", label: "Users", requiredScope: SCOPE_DIRECTORY_READ },
    { href: "/groups", label: "Groups", requiredScope: SCOPE_DIRECTORY_READ },
    { href: "/search", label: "Search", requiredScope: SCOPE_DIRECTORY_READ },
    { href: "/auth-test", label: "Auth test", requiredScope: SCOPE_DIRECTORY_PASSWORD },
    { href: "/schema", label: "Schema", requiredScope: SCOPE_SCHEMA_READ },
    { href: "/audit", label: "Audit", requiredScope: SCOPE_AUDIT_READ },
    { href: "/reset", label: "Reset", requiredScope: SCOPE_LAB_RESET },
    { href: "/export", label: "Export", requiredScope: SCOPE_LAB_EXPORT },
    { href: "/diagnostics", label: "Diagnostics" },
  ];
}

export function navRestriction(item: NavItem, scopes: readonly string[]): string {
  if (item.requiredScope === undefined || hasScope(scopes, item.requiredScope)) {
    return "";
  }
  return missingScopeReason(item.requiredScope);
}

export function insecureReasons(input: {
  secureContext: boolean;
  transports: readonly string[] | undefined;
}): string[] {
  const reasons: string[] = [];
  if (!input.secureContext) {
    reasons.push("The management UI is not in a secure (HTTPS) context.");
  }
  if (input.transports?.some((t) => t.toLowerCase() === "ldap") === true) {
    reasons.push("The directory advertised a cleartext LDAP transport.");
  }
  return reasons;
}

export function scenarioStatus(input: {
  mode: DashboardMode;
  baselineMatch: boolean | undefined;
  resetState: string | undefined;
  markerMatch: boolean | undefined;
}): { label: string; detail: string } {
  if (input.mode === "loading") {
    return {
      label: "Checking",
      detail: "Scenario status is still loading.",
    };
  }
  if (input.mode === "outage") {
    return {
      label: "Unavailable",
      detail: "Scenario status cannot be confirmed while the directory is unreachable.",
    };
  }
  if (input.resetState !== undefined && input.resetState !== "" && input.resetState !== "Ready") {
    return {
      label: `Reset ${input.resetState}`,
      detail: "A soft reset is in progress or failed. Directory writes may be blocked.",
    };
  }
  if (input.baselineMatch === false || input.markerMatch === false) {
    return {
      label: "Baseline mismatch",
      detail: "The applied directory revision does not match the compiled scenario.",
    };
  }
  if (input.mode === "degraded") {
    return {
      label: "Degraded",
      detail: "The compiled scenario is loaded, but readiness checks have not passed.",
    };
  }
  return {
    label: "Applied",
    detail: "The applied baseline matches the compiled scenario revision.",
  };
}

export const emptyTokenField = { token: "" } as const;

export type SessionEndResult = "deleted" | "unauthorized" | "csrf" | "failed";

export function browserSessionComplete(hasCookieSession: boolean, csrfPresent: boolean): boolean {
  return hasCookieSession && csrfPresent;
}

export function canDestroySession(csrfPresent: boolean): boolean {
  return csrfPresent;
}

export function sessionEndInvalidated(result: SessionEndResult): boolean {
  return result === "deleted" || result === "unauthorized";
}
