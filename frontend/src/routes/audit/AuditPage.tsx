import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { listAudit } from "../../api/ops";
import type { AuditEvent } from "../../api/types";
import { useSession } from "../../auth/SessionGate";
import {
  AUDIT_ACTIONS,
  AUDIT_RETENTION_NOTICE,
  DEFAULT_AUDIT_PAGE_SIZE,
  auditQuery,
  safeAuditField,
} from "../../lib/ops-model";
import { queryKeys } from "../../lib/query";
import { hasScope, SCOPE_AUDIT_READ } from "../../lib/session-model";
import { describedBy, QueryStatus, ResourcePage, ScopeNote } from "../shared/ResourcePage";

export function AuditPage() {
  const { session } = useSession();
  const canRead = hasScope(session.scopes, SCOPE_AUDIT_READ);
  const [actionInput, setActionInput] = useState("");
  const [actorInput, setActorInput] = useState("");
  const [action, setAction] = useState("");
  const [actor, setActor] = useState("");
  const [cursor, setCursor] = useState("");
  const [prev, setPrev] = useState<string[]>([]);
  const [copied, setCopied] = useState<string | undefined>();
  const query = auditQuery({ pageSize: DEFAULT_AUDIT_PAGE_SIZE, action, actor, cursor });
  const audit = useQuery({
    queryKey: queryKeys.directory.auditList(query),
    queryFn: () => listAudit(query),
    enabled: canRead,
  });

  return (
    <ResourcePage title="Audit">
      <ScopeNote scopes={session.scopes} required={SCOPE_AUDIT_READ} error={audit.error} />
      <p>{AUDIT_RETENTION_NOTICE}</p>
      {!canRead ? null : (
        <>
          <form
            className="toolbar"
            onSubmit={(event) => {
              event.preventDefault();
              setCursor("");
              setPrev([]);
              setAction(actionInput.trim());
              setActor(actorInput.trim());
            }}
          >
            <div className="field">
              <label htmlFor="audit-action">Action</label>
              <input
                id="audit-action"
                list="audit-action-options"
                value={actionInput}
                autoComplete="off"
                spellCheck={false}
                onChange={(event) => setActionInput(event.target.value)}
              />
              <datalist id="audit-action-options">
                {AUDIT_ACTIONS.map((item) => (
                  <option key={item} value={item} />
                ))}
              </datalist>
            </div>
            <div className="field">
              <label htmlFor="audit-actor">Actor</label>
              <input
                id="audit-actor"
                value={actorInput}
                autoComplete="off"
                spellCheck={false}
                aria-describedby={describedBy(["audit-actor-hint"])}
                onChange={(event) => setActorInput(event.target.value)}
              />
              <p id="audit-actor-hint" className="field-hint">
                Non-secret token or session identifier. Filters apply when you submit.
              </p>
            </div>
            <button type="submit" className="button-primary">Apply filters</button>
            <button
              type="button"
              onClick={() => {
                void audit.refetch();
              }}
            >
              Refresh
            </button>
          </form>
          {audit.data === undefined ? (
            <QueryStatus result={audit} missing="audit events" />
          ) : audit.data.items.length === 0 ? (
            <p className="muted">No audit events match these filters.</p>
          ) : (
            <table>
              <caption>Bounded in-memory audit ring. Expand a row for request ID and revisions.</caption>
              <thead>
                <tr>
                  <th scope="col">Time</th>
                  <th scope="col">Action</th>
                  <th scope="col">Actor</th>
                  <th scope="col">Target</th>
                  <th scope="col">Result</th>
                </tr>
              </thead>
              <tbody>
                {audit.data.items.map((event) => (
                  <AuditRow
                    key={`${event.time}-${event.action}-${event.requestId}`}
                    event={event}
                    copied={copied === event.requestId}
                    onCopy={async () => {
                      try {
                        await navigator.clipboard.writeText(event.requestId);
                        setCopied(event.requestId);
                      } catch {
                        setCopied(undefined);
                      }
                    }}
                  />
                ))}
              </tbody>
            </table>
          )}
          <div className="pager">
            <button
              type="button"
              disabled={prev.length === 0}
              onClick={() => {
                const history = [...prev];
                const back = history.pop() ?? "";
                setPrev(history);
                setCursor(back);
              }}
            >
              Previous
            </button>
            <button
              type="button"
              disabled={audit.data?.nextCursor === undefined || audit.data.nextCursor === ""}
              onClick={() => {
                const next = audit.data?.nextCursor;
                if (next === undefined || next === "") {
                  return;
                }
                setPrev([...prev, cursor]);
                setCursor(next);
              }}
            >
              Next
            </button>
          </div>
        </>
      )}
    </ResourcePage>
  );
}

function AuditRow({
  event,
  copied,
  onCopy,
}: {
  event: AuditEvent;
  copied: boolean;
  onCopy: () => void;
}) {
  const actor = safeAuditField(event.actor);
  const target = safeAuditField(event.target);
  return (
    <tr>
      <td>
        <details>
          <summary>{event.time}</summary>
          <dl>
            <div>
              <dt>Request ID</dt>
              <dd>
                <code>{event.requestId}</code>{" "}
                <button type="button" onClick={onCopy}>
                  Copy request ID
                </button>
                {copied ? <span role="status"> Copied.</span> : null}
              </dd>
            </div>
            <div>
              <dt>Revisions</dt>
              <dd>
                {event.revisions?.before === undefined && event.revisions?.after === undefined
                  ? "—"
                  : `${event.revisions.before ?? "—"} → ${event.revisions.after ?? "—"}`}
              </dd>
            </div>
          </dl>
        </details>
      </td>
      <td>{event.action}</td>
      <td>{actor}</td>
      <td>{target}</td>
      <td>{event.result}</td>
    </tr>
  );
}
