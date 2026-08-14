import type { components, operations, paths } from "@labldap/openapi";

export type { components, operations, paths };

export type User = components["schemas"]["User"];
export type UserSpec = components["schemas"]["UserSpec"];
export type UserPatch = components["schemas"]["UserPatch"];
export type UserPage = components["schemas"]["UserPage"];
export type Group = components["schemas"]["Group"];
export type GroupSpec = components["schemas"]["GroupSpec"];
export type GroupPage = components["schemas"]["GroupPage"];
export type MemberRef = components["schemas"]["MemberRef"];
export type MemberList = components["schemas"]["MemberList"];
export type MembershipSummary = components["schemas"]["MembershipSummary"];
export type PasswordBody = components["schemas"]["PasswordBody"];
export type AttrKV = components["schemas"]["AttrKV"];
export type SessionView = components["schemas"]["SessionView"];
export type SessionCreate = components["schemas"]["SessionCreate"];
export type SessionCreated = components["schemas"]["SessionCreated"];
export type Problem = components["schemas"]["Problem"];
export type HealthStatus = components["schemas"]["HealthStatus"];
export type Scope = components["schemas"]["Scope"];
export type Capabilities = components["schemas"]["Capabilities"];
export type Baseline = components["schemas"]["Baseline"];
export type Diagnostics = components["schemas"]["Diagnostics"];
export type AuditEvent = components["schemas"]["AuditEvent"];
export type AuditPage = components["schemas"]["AuditPage"];
export type BuildInfo = components["schemas"]["BuildInfo"];
