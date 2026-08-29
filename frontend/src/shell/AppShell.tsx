import { useQuery } from "@tanstack/react-query";
import { Link, NavLink, Outlet } from "react-router";
import { getReady } from "../api/directory";
import { listSuffixes } from "../api/entries";
import markUrl from "../assets/mark.svg";
import { useSession } from "../auth/SessionGate";
import { queryKeys } from "../lib/query";
import {
  formatRelativeExpiry,
  hasScope,
  navigationGroups,
  navRestriction,
  primaryWriteScopeChip,
  SCOPE_DIRECTORY_READ,
} from "../lib/session-model";

export function AppShell() {
  const { session, logout, canLogout } = useSession();
  const scopes = session.scopes;
  const canRead = hasScope(scopes, SCOPE_DIRECTORY_READ);
  const writeChip = primaryWriteScopeChip(scopes);
  const suffixes = useQuery({
    queryKey: queryKeys.directory.suffixes,
    queryFn: listSuffixes,
    enabled: canRead,
  });
  const ready = useQuery({
    queryKey: queryKeys.directory.ready,
    queryFn: getReady,
  });
  const suffixChip = canRead && suffixes.isSuccess ? suffixes.data.primary : "";
  const readyLabel = readyLabelFor(ready);

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main">
        Skip to main content
      </a>
      <header className="app-header">
        <div className="brand">
          <img className="brand-mark" src={markUrl} width={28} height={28} alt="" />
          <p className="brand-name">LabLDAP</p>
          {suffixChip !== "" ? <span className="header-chip">{suffixChip}</span> : null}
        </div>
        <div className="header-actions">
          <span className={ready.isSuccess && ready.data === true ? "header-chip header-ready is-ready" : "header-chip header-ready"}>
            {readyLabel}
          </span>
          <span className="header-chip">{formatRelativeExpiry(session.expiresAt, Date.now())}</span>
          {writeChip !== undefined ? <span className="header-chip header-scope">{writeChip}</span> : null}
          <button type="button" onClick={() => void logout()} disabled={!canLogout}>
            Sign out
          </button>
        </div>
      </header>
      {canLogout ? null : (
        <p className="banner banner-warning" role="status">
          This tab has no CSRF secret after a reload.{" "}
          <Link to="/login">Sign in again</Link> with the token before making
          changes. Sign out stays disabled until that re-exchange or the cookie
          expires.
        </p>
      )}
      <div className="app-body">
        <nav className="app-nav" aria-label="Primary">
          {navigationGroups().map((group) => (
            <div key={group.id} className="nav-group">
              {group.label !== undefined ? <p className="nav-group-label">{group.label}</p> : null}
              <ul>
                {group.items.map((item) => {
                  const restriction = navRestriction(item, scopes);
                  return (
                    <li key={item.href}>
                      {restriction === "" ? (
                        <NavLink to={item.href} end={item.href === "/"}>
                          {item.label}
                        </NavLink>
                      ) : (
                        <>
                          <span className="nav-disabled">{item.label}</span>
                          <p className="nav-restriction">{restriction}</p>
                        </>
                      )}
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </nav>
        <Outlet />
      </div>
    </div>
  );
}

function readyLabelFor(ready: { isPending: boolean; isError: boolean; data: boolean | undefined }): string {
  if (ready.isPending) {
    return "Checking";
  }
  if (ready.isError || ready.data !== true) {
    return "unavailable";
  }
  return "Ready";
}
