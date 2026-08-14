import { ifMatchHeader } from "../lib/directory-model";
import { api } from "./client";
import { toApiError } from "./problem";
import type { GroupPage, User, UserPage, UserPatch, UserSpec } from "./types";

export type UserListParams = {
  pageSize: number;
  q?: string;
  cursor?: string;
};

export async function listUsers(params: UserListParams): Promise<UserPage> {
  const { data, error, response } = await api.GET("/api/v1/users", {
    params: { query: params },
  });
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "users unavailable");
  }
  return data;
}

export async function createUser(spec: UserSpec): Promise<User> {
  const { data, error, response } = await api.POST("/api/v1/users", { body: spec });
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "user create failed");
  }
  return data;
}

export async function getUser(id: string): Promise<User> {
  const { data, error, response } = await api.GET("/api/v1/users/{id}", {
    params: { path: { id } },
  });
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "user unavailable");
  }
  return data;
}

export async function updateUser(id: string, patch: UserPatch, revision: string): Promise<User> {
  const { data, error, response } = await api.PATCH("/api/v1/users/{id}", {
    params: { path: { id }, header: ifMatchHeader(revision) },
    body: patch,
  });
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "user update failed");
  }
  return data;
}

export async function deleteUser(id: string, revision: string): Promise<void> {
  const { error, response } = await api.DELETE("/api/v1/users/{id}", {
    params: { path: { id }, header: ifMatchHeader(revision) },
  });
  if (!response.ok) {
    throw toApiError(error, response.status, "user delete failed");
  }
}

export async function setUserPassword(id: string, password: string, revision: string): Promise<void> {
  const { error, response } = await api.POST("/api/v1/users/{id}/password", {
    params: { path: { id } },
    body: { password, revision },
  });
  if (!response.ok) {
    throw toApiError(error, response.status, "password update failed");
  }
}

export async function enableUser(id: string, revision: string): Promise<User> {
  const { data, error, response } = await api.POST("/api/v1/users/{id}/enable", {
    params: { path: { id }, header: ifMatchHeader(revision) },
  });
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "user enable failed");
  }
  return data;
}

export async function disableUser(id: string, revision: string): Promise<User> {
  const { data, error, response } = await api.POST("/api/v1/users/{id}/disable", {
    params: { path: { id }, header: ifMatchHeader(revision) },
  });
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "user disable failed");
  }
  return data;
}

export async function listUserGroups(id: string): Promise<GroupPage> {
  const { data, error, response } = await api.GET("/api/v1/users/{id}/groups", {
    params: { path: { id } },
  });
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "user groups unavailable");
  }
  return data;
}
