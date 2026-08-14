import { ifMatchHeader } from "../lib/directory-model";
import { api } from "./client";
import { toApiError } from "./problem";
import type { Group, GroupPage, GroupSpec, MemberRef, MembershipSummary } from "./types";

export type GroupListParams = {
  pageSize: number;
  q?: string;
  cursor?: string;
};

export async function listGroups(params: GroupListParams): Promise<GroupPage> {
  const { data, error, response } = await api.GET("/api/v1/groups", {
    params: { query: params },
  });
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "groups unavailable");
  }
  return data;
}

export async function createGroup(spec: GroupSpec): Promise<Group> {
  const { data, error, response } = await api.POST("/api/v1/groups", { body: spec });
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "group create failed");
  }
  return data;
}

export async function getGroup(id: string): Promise<Group> {
  const { data, error, response } = await api.GET("/api/v1/groups/{id}", {
    params: { path: { id } },
  });
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "group unavailable");
  }
  return data;
}

export async function deleteGroup(id: string, revision: string): Promise<void> {
  const { error, response } = await api.DELETE("/api/v1/groups/{id}", {
    params: { path: { id }, header: ifMatchHeader(revision) },
  });
  if (!response.ok) {
    throw toApiError(error, response.status, "group delete failed");
  }
}

export async function addGroupMembers(
  id: string,
  members: MemberRef[],
  revision: string,
): Promise<MembershipSummary> {
  const { data, error, response } = await api.POST("/api/v1/groups/{id}/members", {
    params: { path: { id }, header: ifMatchHeader(revision) },
    body: { members },
  });
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "add members failed");
  }
  return data;
}

export async function removeGroupMembers(
  id: string,
  members: MemberRef[],
  revision: string,
): Promise<MembershipSummary> {
  const { data, error, response } = await api.DELETE("/api/v1/groups/{id}/members", {
    params: { path: { id }, header: ifMatchHeader(revision) },
    body: { members },
  });
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "remove members failed");
  }
  return data;
}

export async function replaceGroupMembers(
  id: string,
  members: MemberRef[],
  revision: string,
): Promise<MembershipSummary> {
  const { data, error, response } = await api.PUT("/api/v1/groups/{id}/members", {
    params: { path: { id }, header: ifMatchHeader(revision) },
    body: { members },
  });
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "replace members failed");
  }
  return data;
}
