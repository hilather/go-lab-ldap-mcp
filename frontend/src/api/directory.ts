import { api } from "./client";
import { toApiError } from "./problem";
import type { AuditEvent, Baseline, BuildInfo, Capabilities, Diagnostics } from "./types";

export async function getReady(): Promise<boolean> {
  const { data, response } = await api.GET("/health/ready");
  return response.ok && data?.status === "ready";
}

export async function getDiagnostics(): Promise<Diagnostics> {
  const { data, error, response } = await api.GET("/api/v1/diagnostics");
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "diagnostics unavailable");
  }
  return data;
}

export async function getCapabilities(): Promise<Capabilities> {
  const { data, error, response } = await api.GET("/api/v1/capabilities");
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "capabilities unavailable");
  }
  return data;
}

export async function getBaseline(): Promise<Baseline> {
  const { data, error, response } = await api.GET("/api/v1/baseline");
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "baseline unavailable");
  }
  return data;
}

export async function getVersion(): Promise<BuildInfo> {
  const { data, error, response } = await api.GET("/api/v1/version");
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "version unavailable");
  }
  return data;
}

export async function getRecentAudit(): Promise<AuditEvent[]> {
  const { data, error, response } = await api.GET("/api/v1/audit", {
    params: { query: { pageSize: 5 } },
  });
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "audit unavailable");
  }
  return data.items;
}
