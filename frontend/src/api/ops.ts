import { getMemoryBearer, getMemoryCSRF } from "./token";
import { api } from "./client";
import { toApiError } from "./problem";
import type { AuditPage, ResetRequest, ResetStatus } from "./types";

export type AuditListParams = {
  pageSize: number;
  action?: string;
  actor?: string;
  cursor?: string;
};

export async function listAudit(params: AuditListParams): Promise<AuditPage> {
  const { data, error, response } = await api.GET("/api/v1/audit", {
    params: { query: params },
  });
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "audit unavailable");
  }
  return data;
}

export async function getReset(): Promise<ResetStatus> {
  const { data, error, response } = await api.GET("/api/v1/reset");
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "reset status unavailable");
  }
  return data;
}

export async function startReset(req: ResetRequest): Promise<ResetStatus> {
  const { data, error, response } = await api.POST("/api/v1/reset", { body: req });
  if ((response.status === 202 || response.status === 409) && data !== undefined && isResetStatus(data)) {
    return data;
  }
  throw toApiError(error, response.status, "reset failed");
}

export async function downloadExport(omitSecrets: boolean): Promise<void> {
  const url = omitSecrets ? "/api/v1/export" : "/api/v1/export?omitSecrets=false";
  const headers = new Headers({ Accept: "text/plain" });
  const csrf = getMemoryCSRF();
  if (csrf !== undefined) {
    headers.set("X-CSRF-Token", csrf);
  }
  const token = getMemoryBearer();
  if (token !== undefined) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  const response = await fetch(url, { credentials: "same-origin", headers, cache: "no-store" });
  if (!response.ok) {
    let problem: unknown;
    try {
      problem = await response.json();
    } catch {
      problem = undefined;
    }
    throw toApiError(problem, response.status, "export failed");
  }
  const blob = await response.blob();
  const href = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = href;
  link.download = "labldap-export.ldif";
  link.rel = "noopener";
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(href);
}

function isResetStatus(value: unknown): value is ResetStatus {
  return typeof value === "object" && value !== null && ("state" in value || "phase" in value);
}
