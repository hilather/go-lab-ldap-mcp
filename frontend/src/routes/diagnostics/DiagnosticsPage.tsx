import { useQuery } from "@tanstack/react-query";
import { getDiagnostics } from "../../api/directory";
import { useSession } from "../../auth/SessionGate";
import { queryKeys } from "../../lib/query";
import { QueryStatus, ResourcePage } from "../shared/ResourcePage";

export function DiagnosticsPage() {
  useSession();
  const diag = useQuery({
    queryKey: queryKeys.directory.diagnostics,
    queryFn: getDiagnostics,
  });

  return (
    <ResourcePage title="Diagnostics">
      <p>Authenticated operator view. Paths, DNs, tokens, and passwords are not included.</p>
      {diag.data === undefined ? (
        <QueryStatus result={diag} missing="diagnostics" />
      ) : (
        <section aria-labelledby="diagnostics-heading">
          <h2 id="diagnostics-heading">Component status</h2>
          <dl>
            <div>
              <dt>Ready</dt>
              <dd>{diag.data.ready ? "Yes" : "No"}</dd>
            </div>
            <div>
              <dt>Marker match</dt>
              <dd>{diag.data.markerMatch ? "Yes" : "No"}</dd>
            </div>
            <div>
              <dt>Reset state</dt>
              <dd>{diag.data.reset.state}</dd>
            </div>
            <div>
              <dt>Pool active</dt>
              <dd>{diag.data.pool.active}</dd>
            </div>
            <div>
              <dt>Pool idle</dt>
              <dd>{diag.data.pool.idle}</dd>
            </div>
            <div>
              <dt>Pool max</dt>
              <dd>{diag.data.pool.max}</dd>
            </div>
          </dl>
        </section>
      )}
    </ResourcePage>
  );
}
