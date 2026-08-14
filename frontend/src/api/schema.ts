import { api } from "./client";
import { toApiError } from "./problem";
import type { AttributeType, ObjectClass, RootDSE, Schema } from "./types";

export async function getRootDSE(): Promise<RootDSE> {
  const { data, error, response } = await api.GET("/api/v1/rootdse");
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "root DSE unavailable");
  }
  return data;
}

export async function getSchema(): Promise<Schema> {
  const { data, error, response } = await api.GET("/api/v1/schema");
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "schema unavailable");
  }
  return data;
}

export async function getObjectClass(name: string): Promise<ObjectClass> {
  const { data, error, response } = await api.GET("/api/v1/schema/objectclasses/{name}", {
    params: { path: { name } },
  });
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "object class unavailable");
  }
  return data;
}

export async function getAttributeType(name: string): Promise<AttributeType> {
  const { data, error, response } = await api.GET("/api/v1/schema/attributes/{name}", {
    params: { path: { name } },
  });
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "attribute type unavailable");
  }
  return data;
}
