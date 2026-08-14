import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { Link } from "react-router";
import { getBaseline, getCapabilities, getDiagnostics, getReady, getRecentAudit, getVersion } from "../api/directory";
import { isApiError } from "../api/problem";
import type { AuditEvent } from "../api/types";
import { useSession } from "../auth/SessionGate";
import { queryKeys } from "../lib/query";
import { safeAuditField } from "../lib/ops-model";
import {
  dashboardMode,
  hasScope,
  insecureReasons,
  quickActions,
  scenarioStatus,
  SCOPE_AUDIT_READ,
  SCOPE_DIRECTORY_READ,
  statusPresentation,
} from "../lib/session-model";

export function DashboardPage() {
  const { session } = useSession();
  const scopes = session.scopes;
  const canReadDirectory = hasScope(scopes, SCOPE_DIRECTORY_READ);
  const canReadAudit = hasScope(scopes, SCOPE_AUDIT_READ);

  const readyQuery = useQuery({
    queryKey: queryKeys.directory.ready,
    queryFn: getReady,
  });
  const diagnosticsQuery = useQuery({
    queryKey: queryKeys.directory.diagnostics,
    queryFn: getDiagnostics,
  });
  const capabilitiesQuery = useQuery({
    queryKey: queryKeys.directory.capabilities,
    queryFn: getCapabilities,
    enabled: canReadDirectory,
  });
  const baselineQuery = useQuery({
    queryKey: queryKeys.directory.baseline,
    queryFn: getBaseline,
    enabled: canReadDirectory,
  });
  const versionQuery = useQuery({
    queryKey: queryKeys.directory.version,
    queryFn: getVersion,
    enabled: canReadDirectory,
  });
  const auditQuery = useQuery({
    queryKey: queryKeys.directory.audit,
    queryFn: getRecentAudit,
    enabled: canReadAudit,
  });

  const directoryUnreachable =
    isUnavailable(diagnosticsQuery.error) ||
    isUnavailable(capabilitiesQuery.error) ||
    isUnavailable(baselineQuery.error);
  const ready =
    diagnosticsQuery.data !== undefined ? diagnosticsQuery.data.ready : readyQuery.data === true;
  const settled =
    diagnosticsQuery.data !== undefined ||
    diagnosticsQuery.isError ||
    readyQuery.data === true;
  const mode = dashboardMode({ ready, directoryUnreachable, settled });
  const status = statusPresentation(mode);
  const scenario = scenarioStatus({
    mode,
    baselineMatch: baselineQuery.data?.match,
    resetState: diagnosticsQuery.data?.reset.state,
    markerMatch: diagnosticsQuery.data?.markerMatch,
  });
  const transports = capabilitiesQuery.data?.transports;
  const banners = insecureReasons({
    secureContext: globalThis.isSecureContext === true,
    transports,
  });
  const actions = quickActions(scopes);

  return (
    <main id="main" className="dashboard">
      <h1>Dashboard</h1>
      {banners.map((reason) => (
        <p key={reason} className="banner banner-insecure" role="alert">
          Insecure lab configuration: {reason}
        </p>
      ))}

      <section className={`status-card status-${status.mode}`} aria-labelledby="status-heading">
        <h2 id="status-heading">Directory status</h2>
        <p className="status-line">
          <span aria-hidden="true">{status.symbol}</span> {status.label}
        </p>
        <p>{status.detail}</p>
      </section>

      {mode === "outage" ? (
        <section className="outage" aria-labelledby="outage-heading">
          <h2 id="outage-heading">Directory outage</h2>
          <p>
            The dashboard is still available. Directory reads failed, so engine,
            baseline, and transport details may be incomplete until the engine
            recovers.
          </p>
          {diagnosticsQuery.data !== undefined ? (
            <p>
              Diagnostics report ready={String(diagnosticsQuery.data.ready)}, marker
              match={String(diagnosticsQuery.data.markerMatch)}, reset{" "}
              {diagnosticsQuery.data.reset.state}.
            </p>
          ) : (
            <QueryNote result={diagnosticsQuery} missing="diagnostics" />
          )}
        </section>
      ) : null}

      <section aria-labelledby="scenario-heading">
        <h2 id="scenario-heading">Scenario status</h2>
        <p>
          <strong>{scenario.label}.</strong> {scenario.detail}
        </p>
      </section>

      <section aria-labelledby="engine-heading">
        <h2 id="engine-heading">Engine</h2>
        {permissionOrError(canReadDirectory, SCOPE_DIRECTORY_READ, capabilitiesQuery.error) ??
          (capabilitiesQuery.data !== undefined ? (
            <dl>
              <div>
                <dt>Vendor</dt>
                <dd>{display(capabilitiesQuery.data.engineVendor)}</dd>
              </div>
              <div>
                <dt>Engine version</dt>
                <dd>{display(capabilitiesQuery.data.engineVersion)}</dd>
              </div>
              <div>
                <dt>Adapter</dt>
                <dd>{display(capabilitiesQuery.data.adapterVersion)}</dd>
              </div>
              <div>
                <dt>Required capabilities</dt>
                <dd>
                  {capabilitiesQuery.data.requiredOK ? "Met" : "Not met"}
                </dd>
              </div>
              <div>
                <dt>Password scheme</dt>
                <dd>{display(capabilitiesQuery.data.passwordScheme)}</dd>
              </div>
              {versionQuery.data !== undefined ? (
                <div>
                  <dt>Control version</dt>
                  <dd>
                    {versionQuery.data.version} ({versionQuery.data.revision})
                  </dd>
                </div>
              ) : null}
            </dl>
          ) : (
            <QueryNote result={capabilitiesQuery} missing="engine capabilities" />
          ))}
      </section>

      <section aria-labelledby="baseline-heading">
        <h2 id="baseline-heading">Baseline</h2>
        {permissionOrError(canReadDirectory, SCOPE_DIRECTORY_READ, baselineQuery.error) ??
          (baselineQuery.data !== undefined ? (
            <dl>
              <div>
                <dt>Match</dt>
                <dd>{baselineQuery.data.match ? "Yes — revisions match" : "No — revisions differ"}</dd>
              </div>
              <div>
                <dt>Expected</dt>
                <dd>
                  <code>{display(baselineQuery.data.expectedRevision)}</code>
                </dd>
              </div>
              <div>
                <dt>Applied</dt>
                <dd>
                  <code>{display(baselineQuery.data.appliedRevision)}</code>
                </dd>
              </div>
              <div>
                <dt>Control</dt>
                <dd>
                  <code>{display(baselineQuery.data.controlRevision)}</code>
                </dd>
              </div>
            </dl>
          ) : (
            <QueryNote result={baselineQuery} missing="baseline" />
          ))}
      </section>

      <section aria-labelledby="transport-heading">
        <h2 id="transport-heading">Transport</h2>
        {permissionOrError(canReadDirectory, SCOPE_DIRECTORY_READ, capabilitiesQuery.error) ??
          (transports !== undefined ? (
            transports.length === 0 ? (
              <p>No directory transports were advertised.</p>
            ) : (
              <ul>
                {transports.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            )
          ) : (
            <QueryNote result={capabilitiesQuery} missing="transport list" />
          ))}
      </section>

      <section aria-labelledby="actions-heading">
        <h2 id="actions-heading">Quick actions</h2>
        <ul className="action-list">
          {actions.map((action) => (
            <li key={action.id}>
              {action.enabled ? (
                <Link to={action.href}>{action.label}</Link>
              ) : (
                <p>
                  <span className="action-disabled">{action.label}</span>
                  <span className="action-reason"> {action.reason}</span>
                </p>
              )}
            </li>
          ))}
        </ul>
      </section>

      <section aria-labelledby="audit-heading">
        <h2 id="audit-heading">Recent audit</h2>
        {permissionOrError(canReadAudit, SCOPE_AUDIT_READ, auditQuery.error) ??
          (auditQuery.data !== undefined ? (
            <AuditList events={auditQuery.data} />
          ) : (
            <QueryNote result={auditQuery} missing="audit events" />
          ))}
      </section>
    </main>
  );
}

function AuditList({ events }: { events: AuditEvent[] }) {
  if (events.length === 0) {
    return <p>No audit events are in the in-memory ring yet.</p>;
  }
  return (
    <table>
      <caption>Latest events from the in-memory audit ring</caption>
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
        {events.map((event) => (
          <tr key={`${event.time}-${event.action}-${event.requestId}`}>
            <td>{event.time}</td>
            <td>{event.action}</td>
            <td>{safeAuditField(event.actor)}</td>
            <td>{safeAuditField(event.target)}</td>
            <td>{event.result}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function permissionOrError(
  allowed: boolean,
  scope: string,
  error: unknown,
): ReactNode | undefined {
  if (!allowed) {
    return <p>Requires scope {scope}.</p>;
  }
  if (isApiError(error) && error.forbidden) {
    const required = error.requiredScope() ?? scope;
    return <p>Requires scope {required}.</p>;
  }
  return undefined;
}

function QueryNote({
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
  if (result.error !== null && result.error !== undefined) {
    return <p>Could not load {missing}.</p>;
  }
  return <p>No {missing} yet.</p>;
}

function isUnavailable(error: unknown): boolean {
  return isApiError(error) && error.directoryUnavailable;
}

function display(value: string): string {
  return value === "" ? "—" : value;
}
