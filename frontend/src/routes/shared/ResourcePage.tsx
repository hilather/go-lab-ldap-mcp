import type { ReactNode } from "react";
import { isApiError } from "../../api/problem";
import { hasScope } from "../../lib/session-model";

export function ResourcePage({ title, children }: { title: string; children: ReactNode }) {
  return (
    <main id="main" className="resource-page">
      <h1>{title}</h1>
      {children}
    </main>
  );
}

export function ScopeNote({
  scopes,
  required,
  error,
}: {
  scopes: readonly string[];
  required: string;
  error?: unknown;
}) {
  if (!hasScope(scopes, required)) {
    return <p>Requires scope {required}.</p>;
  }
  if (isApiError(error) && error.forbidden) {
    return <p>Requires scope {error.requiredScope() ?? required}.</p>;
  }
  return null;
}

export function QueryStatus({
  result,
  missing,
}: {
  result: { isPending: boolean; error: unknown };
  missing: string;
}) {
  if (result.isPending) {
    return <p role="status">Loading {missing}…</p>;
  }
  if (isApiError(result.error) && result.error.directoryUnavailable) {
    return <p>Directory outage: {missing} unavailable.</p>;
  }
  if (isApiError(result.error) && result.error.status === 404) {
    return <p>{missing} was not found.</p>;
  }
  if (result.error !== null && result.error !== undefined) {
    return <p>Could not load {missing}.</p>;
  }
  return null;
}

export function FormError({ id, message }: { id: string; message?: string | undefined }) {
  if (message === undefined || message === "") {
    return null;
  }
  return (
    <p id={id} className="field-error" role="alert">
      {message}
    </p>
  );
}

export function describedBy(ids: readonly (string | undefined)[]): string | undefined {
  const joined = ids.filter((id): id is string => id !== undefined && id !== "").join(" ");
  return joined === "" ? undefined : joined;
}
