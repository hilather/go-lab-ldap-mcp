import { NavLink, Outlet } from "react-router";
import { getMemoryCSRF } from "../api/token";
import { useSession } from "../auth/SessionGate";
import { navigationItems, navRestriction } from "../lib/session-model";

export function AppShell() {
  const { session, logout } = useSession();
  const csrfMissing = getMemoryCSRF() === undefined;
  const scopes = session.scopes;

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main">
        Skip to main content
      </a>
      <header className="app-header">
        <div className="brand">
          <p className="brand-name">LabLDAP</p>
          <p className="brand-meta">
            Session {session.id} · expires {formatExpiry(session.expiresAt)}
          </p>
        </div>
        <div className="header-actions">
          <section className="scope-list" aria-labelledby="header-scopes-heading">
            <h2 id="header-scopes-heading">Granted scopes</h2>
            {scopes.length === 0 ? (
              <p>None</p>
            ) : (
              <ul>
                {scopes.map((scope) => (
                  <li key={scope}>{scope}</li>
                ))}
              </ul>
            )}
          </section>
          <button type="button" onClick={() => void logout()}>
            Sign out
          </button>
        </div>
      </header>
      {csrfMissing ? (
        <p className="banner banner-warning" role="status">
          This tab has no CSRF secret after a reload. Sign in again before making changes.
        </p>
      ) : null}
      <div className="app-body">
        <nav className="app-nav" aria-label="Primary">
          <ul>
            {navigationItems().map((item) => {
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
        </nav>
        <Outlet />
      </div>
    </div>
  );
}

function formatExpiry(value: string): string {
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) {
    return value;
  }
  return new Date(ms).toISOString();
}
