import { useState } from "react";
import { downloadExport } from "../../api/ops";
import { isApiError } from "../../api/problem";
import { useSession } from "../../auth/SessionGate";
import { canSubmitExport, exportConfirmNeeded } from "../../lib/ops-model";
import { hasScope, SCOPE_LAB_EXPORT } from "../../lib/session-model";
import { describedBy, ResourcePage, ScopeNote } from "../shared/ResourcePage";

export function ExportPage() {
  const { session } = useSession();
  const gate = canSubmitExport({ hasExport: hasScope(session.scopes, SCOPE_LAB_EXPORT) });
  const [omitSecrets, setOmitSecrets] = useState(true);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | undefined>();
  const needsConfirm = exportConfirmNeeded(omitSecrets);
  const canDownload = gate.ok && (!needsConfirm || confirmed) && !busy;

  return (
    <ResourcePage title="Export">
      <ScopeNote scopes={session.scopes} required={SCOPE_LAB_EXPORT} />
      <p>
        Download a redacted LDIF of the managed suffix. The request uses the
        current session. Secret attributes are omitted unless you explicitly
        include them.
      </p>
      {!gate.ok ? <p>{gate.reason}</p> : null}
      <form
        method="post"
        onSubmit={(event) => {
          event.preventDefault();
          if (!canDownload) {
            return;
          }
          void (async () => {
            setBusy(true);
            setNotice(undefined);
            try {
              await downloadExport(omitSecrets);
              setNotice("Export download started.");
            } catch (err) {
              setNotice(isApiError(err) ? err.message : "Export failed.");
            } finally {
              setBusy(false);
            }
          })();
        }}
      >
        <div className="field">
          <label htmlFor="export-omit">
            <input
              id="export-omit"
              type="checkbox"
              checked={omitSecrets}
              onChange={(event) => {
                setOmitSecrets(event.target.checked);
                setConfirmed(false);
              }}
            />{" "}
            Omit secrets (recommended)
          </label>
        </div>
        {needsConfirm ? (
          <div className="field">
            <label htmlFor="export-confirm">
              <input
                id="export-confirm"
                type="checkbox"
                checked={confirmed}
                aria-describedby={describedBy(["export-confirm-hint"])}
                onChange={(event) => setConfirmed(event.target.checked)}
              />{" "}
              I understand this export may include hashed secret attributes
            </label>
            <p id="export-confirm-hint" className="field-hint">
              Cleartext passwords are still not included. Confirmation is required
              when omitSecrets is off.
            </p>
          </div>
        ) : null}
        <div className="form-actions">
          <button type="submit" disabled={!canDownload}>
            {busy ? "Exporting…" : "Download LDIF"}
          </button>
        </div>
      </form>
      {notice !== undefined ? <p role="status">{notice}</p> : null}
    </ResourcePage>
  );
}
