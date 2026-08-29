import { QueryClient } from "@tanstack/react-query";

export const sessionQueryKey = ["session"] as const;
export const directoryQueryKey = ["directory"] as const;

const usersQueryKey = [...directoryQueryKey, "users"] as const;
const groupsQueryKey = [...directoryQueryKey, "groups"] as const;

export const queryKeys = {
  session: sessionQueryKey,
  directory: {
    all: directoryQueryKey,
    ready: [...directoryQueryKey, "ready"] as const,
    diagnostics: [...directoryQueryKey, "diagnostics"] as const,
    capabilities: [...directoryQueryKey, "capabilities"] as const,
    suffixes: [...directoryQueryKey, "suffixes"] as const,
    tree: (base: string, cursor: string) => [...directoryQueryKey, "tree", base, cursor] as const,
    entry: (dn: string) => [...directoryQueryKey, "entry", dn] as const,
    baseline: [...directoryQueryKey, "baseline"] as const,
    version: [...directoryQueryKey, "version"] as const,
    audit: [...directoryQueryKey, "audit"] as const,
    auditList: (q: { pageSize: number; action?: string; actor?: string; cursor?: string }) =>
      [...directoryQueryKey, "audit", "list", q] as const,
    schema: [...directoryQueryKey, "schema"] as const,
    rootdse: [...directoryQueryKey, "rootdse"] as const,
    reset: [...directoryQueryKey, "reset"] as const,
  },
  users: {
    all: usersQueryKey,
    list: (q: { pageSize: number; q?: string; cursor?: string }) => [...usersQueryKey, "list", q] as const,
    detail: (id: string) => [...usersQueryKey, "detail", id] as const,
    groups: (id: string) => [...usersQueryKey, "groups", id] as const,
  },
  groups: {
    all: groupsQueryKey,
    list: (q: { pageSize: number; q?: string; cursor?: string }) => [...groupsQueryKey, "list", q] as const,
    detail: (id: string) => [...groupsQueryKey, "detail", id] as const,
  },
};

function isUnauthorizedError(err: unknown): boolean {
  return typeof err === "object" && err !== null && "status" in err && err.status === 401;
}

export function createAppQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: (count, err) => {
          if (isUnauthorizedError(err)) {
            return false;
          }
          return count < 1;
        },
        refetchOnWindowFocus: false,
        staleTime: 10_000,
      },
    },
  });
}

export function invalidateUsersAndGroups(client: QueryClient): Promise<void> {
  return Promise.all([
    client.invalidateQueries({ queryKey: usersQueryKey }),
    client.invalidateQueries({ queryKey: groupsQueryKey }),
  ]).then(() => undefined);
}

export function invalidateAfterReset(client: QueryClient): Promise<void> {
  return client.invalidateQueries({ queryKey: directoryQueryKey }).then(() => undefined);
}

export function clearDirectoryQueryData(client: QueryClient): void {
  client.removeQueries({ queryKey: directoryQueryKey });
}

export function clearSessionQueryData(client: QueryClient): void {
  client.removeQueries({ queryKey: sessionQueryKey });
  clearDirectoryQueryData(client);
}
