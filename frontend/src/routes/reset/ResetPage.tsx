import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { getBaseline } from "../../api/directory";
import { getReset, startReset } from "../../api/ops";
import { isApiError } from "../../api/problem";
import type { ResetStatus } from "../../api/types";
import { useSession } from "../../auth/SessionGate";
import { canSubmitReset, isResetInProgress, resetPollInterval } from "../../lib/ops-model";
import { invalidateAfterReset, queryKeys } from "../../lib/query";
import { hasScope, SCOPE_DIRECTORY_READ, SCOPE_LAB_RESET } from "../../lib/session-model";
import { describedBy, QueryStatus, ResourcePage, ScopeNote } from "../shared/ResourcePage";
import { LiveRegion } from "../shared/SafeText";

export function ResetPage() {
  const queryClient = useQueryClient();
  const { session, canLogout } = useSession();
  const canRead = hasScope(session.scopes, SCOPE_DIRECTORY_READ);
  const [name, setName] = useState("");
  const [revision, setRevision] = useState("");
  const [notice, setNotice] = useState<string | undefined>();
  const [submitting, setSubmitting] = useState(false);
  const wasInProgress = useRef(false);
  const baseline = useQuery({
    queryKey: queryKeys.directory.baseline,
    queryFn: getBaseline,
    enabled: canRead,
  });
  const resetQuery = useQuery({
    queryKey: queryKeys.directory.reset,
    queryFn: getReset,
    enabled: hasScope(session.scopes, SCOPE_LAB_RESET),
    refetchInterval: (query) => resetPollInterval(query.state.data?.state),
  });
  const currentRevision = baseline.data?.expectedRevision ?? "";
  const inProgress = submitting || isResetInProgress(resetQuery.data?.state);
  const gate = canSubmitReset({
    hasReset: hasScope(session.scopes, SCOPE_LAB_RESET),
    csrfPresent: canLogout,
    name,
    revision,
    currentRevision,
    inProgress,
  });

  useEffect(() => {
    const state = resetQuery.data?.state;
    const now = isResetInProgress(state);
    const ended = wasInProgress.current && !now;
    wasInProgress.current = now;
    if (!ended) {
      return;
    }
    void invalidateAfterReset(queryClient);
    if (state === "Ready") {
      setNotice("Reset completed. Baseline, users, groups, capabilities, and audit were refreshed.");
    } else if (state === "Failed") {
      setNotice(resetQuery.data?.error || "Reset failed. See diagnostics for recovery.");
    }
  }, [queryClient, resetQuery.data?.error, resetQuery.data?.state]);

  return (
    <ResourcePage title="Soft reset">
      <ScopeNote scopes={session.scopes} required={SCOPE_LAB_RESET} error={resetQuery.error} />
      <p>
        Soft reset rebuilds the managed suffix from the compiled baseline. It does
        not restart containers or write the bootstrap marker. Type the exact
        scenario name and the current compiled revision.
      </p>
      {canRead && baseline.data === undefined ? (
        <QueryStatus result={baseline} missing="baseline revision" />
      ) : null}
      {currentRevision !== "" ? (
        <p>
          Current compiled revision: <code>{currentRevision}</code>
        </p>
      ) : (
        <p>Load the compiled revision from baseline, or type it if you already have it.</p>
      )}
      <ResetStatusView status={resetQuery.data} />
      <form
        method="post"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          if (!gate.ok || submitting) {
            return;
          }
          void (async () => {
            setSubmitting(true);
            setNotice(undefined);
            try {
              const status = await startReset({ name: name.trim(), expectedRevision: revision.trim() });
              queryClient.setQueryData(queryKeys.directory.reset, status);
              if (isResetInProgress(status.state)) {
                wasInProgress.current = true;
              } else {
                await invalidateAfterReset(queryClient);
                if (status.state === "Failed") {
                  setNotice(status.error || "Reset failed. See diagnostics for recovery.");
                } else {
                  setNotice("Reset completed. Baseline, users, groups, capabilities, and audit were refreshed.");
                }
              }
              await resetQuery.refetch();
            } catch (err) {
              setNotice(isApiError(err) ? err.message : "Reset was not accepted.");
            } finally {
              setSubmitting(false);
            }
          })();
        }}
      >
        <div className="field">
          <label htmlFor="reset-name">Scenario name</label>
          <input
            id="reset-name"
            value={name}
            autoComplete="off"
            spellCheck={false}
            aria-required="true"
            aria-describedby={describedBy(["reset-name-hint"])}
            onChange={(event) => setName(event.target.value)}
          />
          <p id="reset-name-hint" className="field-hint">
            Must match compiled metadata.name exactly.
          </p>
        </div>
        <div className="field">
          <label htmlFor="reset-revision">Expected revision</label>
          <input
            id="reset-revision"
            value={revision}
            autoComplete="off"
            spellCheck={false}
            aria-required="true"
            aria-describedby={describedBy(["reset-revision-hint"])}
            onChange={(event) => setRevision(event.target.value)}
          />
          <p id="reset-revision-hint" className="field-hint">
            Type the current compiled directory revision shown above.
          </p>
        </div>
        {!gate.ok ? <p>{gate.reason}</p> : null}
        <div className="form-actions">
          <button type="submit" disabled={!gate.ok || submitting}>
            {submitting || inProgress ? "Reset in progress…" : "Start soft reset"}
          </button>
        </div>
      </form>
      <LiveRegion message={notice} />
    </ResourcePage>
  );
}

function ResetStatusView({ status }: { status: ResetStatus | undefined }) {
  if (status === undefined) {
    return null;
  }
  return (
    <section aria-labelledby="reset-status-heading">
      <h2 id="reset-status-heading">Operation status</h2>
      <dl>
        <div>
          <dt>State</dt>
          <dd>{status.state ?? "—"}</dd>
        </div>
        <div>
          <dt>Phase</dt>
          <dd>{status.phase ?? "—"}</dd>
        </div>
        <div>
          <dt>Counts</dt>
          <dd>
            deleted {status.counts?.deleted ?? 0}, users {status.counts?.users ?? 0}, groups{" "}
            {status.counts?.groups ?? 0}, extra {status.counts?.extra ?? 0}
          </dd>
        </div>
        <div>
          <dt>Expected</dt>
          <dd>
            <code>{status.expectedRevision ?? "—"}</code>
          </dd>
        </div>
        <div>
          <dt>Applied</dt>
          <dd>
            <code>{status.appliedRevision ?? "—"}</code>
          </dd>
        </div>
        {status.error !== undefined && status.error !== "" ? (
          <div>
            <dt>Error</dt>
            <dd>{status.error}</dd>
          </div>
        ) : null}
        {status.recovery !== undefined && status.recovery !== "" ? (
          <div>
            <dt>Recovery</dt>
            <dd>{status.recovery}</dd>
          </div>
        ) : null}
      </dl>
    </section>
  );
}
