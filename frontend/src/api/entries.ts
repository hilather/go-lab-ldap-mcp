import { ifMatchHeader } from "../lib/directory-model";
import { api } from "./client";
import { toApiError } from "./problem";
import type { DirectoryEntry, EntryMove, EntryPatch, EntrySpec, SuffixList, TreePage } from "./types";

export async function listSuffixes(): Promise<SuffixList> {
  const { data, error, response } = await api.GET("/api/v1/suffixes");
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "suffixes unavailable");
  }
  return data;
}

export async function listTree(base: string, cursor?: string): Promise<TreePage> {
  const body: { base: string; cursor?: string } = { base };
  if (cursor !== undefined && cursor !== "") {
    body.cursor = cursor;
  }
  const { data, error, response } = await api.POST("/api/v1/tree", {
    body,
  });
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "tree unavailable");
  }
  return data;
}

export async function getEntry(dn: string): Promise<DirectoryEntry> {
  const { data, error, response } = await api.GET("/api/v1/entries", {
    params: { query: { dn } },
  });
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "entry unavailable");
  }
  return data;
}

export async function createEntry(spec: EntrySpec): Promise<DirectoryEntry> {
  const { data, error, response } = await api.POST("/api/v1/entries", { body: spec });
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "entry create failed");
  }
  return data;
}

export async function updateEntry(dn: string, patch: EntryPatch, revision: string): Promise<DirectoryEntry> {
  const { data, error, response } = await api.PATCH("/api/v1/entries", {
    params: { query: { dn }, header: ifMatchHeader(revision) },
    body: patch,
  });
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "entry update failed");
  }
  return data;
}

export async function deleteEntry(dn: string, revision: string, recursive: boolean): Promise<void> {
  const { error, response } = await api.DELETE("/api/v1/entries", {
    params: { query: { dn, confirm: true, recursive }, header: ifMatchHeader(revision) },
  });
  if (!response.ok) {
    throw toApiError(error, response.status, "entry delete failed");
  }
}

export async function moveEntry(body: EntryMove, revision: string): Promise<DirectoryEntry> {
  const { data, error, response } = await api.POST("/api/v1/entries/move", {
    params: { header: ifMatchHeader(revision) },
    body,
  });
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "entry move failed");
  }
  return data;
}
