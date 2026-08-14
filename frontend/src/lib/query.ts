import { QueryClient } from "@tanstack/react-query";

export const sessionQueryKey = ["session"] as const;
export const directoryQueryKey = ["directory"] as const;

export const queryKeys = {
  session: sessionQueryKey,
  directory: {
    all: directoryQueryKey,
    ready: [...directoryQueryKey, "ready"] as const,
    diagnostics: [...directoryQueryKey, "diagnostics"] as const,
    capabilities: [...directoryQueryKey, "capabilities"] as const,
    baseline: [...directoryQueryKey, "baseline"] as const,
    version: [...directoryQueryKey, "version"] as const,
    audit: [...directoryQueryKey, "audit"] as const,
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

export function clearDirectoryQueryData(client: QueryClient): void {
  client.removeQueries({ queryKey: directoryQueryKey });
}

export function clearSessionQueryData(client: QueryClient): void {
  client.removeQueries({ queryKey: sessionQueryKey });
  clearDirectoryQueryData(client);
}
