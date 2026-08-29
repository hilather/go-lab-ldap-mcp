import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link } from "react-router";
import { isApiError } from "../../api/problem";
import type { User } from "../../api/types";
import { listUsers } from "../../api/users";
import { useSession } from "../../auth/SessionGate";
import {
  ariaSort,
  canSubmitMutation,
  DEFAULT_LIST_PAGE_SIZE,
  emptyListMessage,
  listQuery,
  nextSortDir,
  sortUsers,
  type SortDir,
  type UserSortKey,
} from "../../lib/directory-model";
import { queryKeys } from "../../lib/query";
import { hasScope, SCOPE_DIRECTORY_READ, SCOPE_DIRECTORY_WRITE } from "../../lib/session-model";
import { QueryStatus, ResourcePage, ScopeNote } from "../shared/ResourcePage";

export function UserListPage() {
  const { session, canLogout } = useSession();
  const canRead = hasScope(session.scopes, SCOPE_DIRECTORY_READ);
  const createGate = canSubmitMutation({
    hasWrite: hasScope(session.scopes, SCOPE_DIRECTORY_WRITE),
    csrfPresent: canLogout,
  });
  const [qInput, setQInput] = useState("");
  const [q, setQ] = useState("");
  const [cursor, setCursor] = useState("");
  const [prev, setPrev] = useState<string[]>([]);
  const [sortKey, setSortKey] = useState<UserSortKey>("id");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const query = listQuery({ pageSize: DEFAULT_LIST_PAGE_SIZE, q, cursor });
  const usersQuery = useQuery({
    queryKey: queryKeys.users.list(query),
    queryFn: () => listUsers(query),
    enabled: canRead,
  });
  const items = useMemo(
    () => sortUsers(usersQuery.data?.items ?? [], sortKey, sortDir),
    [usersQuery.data?.items, sortKey, sortDir],
  );
  const searching = q.trim() !== "";

  return (
    <ResourcePage title="Users">
      <ScopeNote scopes={session.scopes} required={SCOPE_DIRECTORY_READ} error={usersQuery.error} />
      {!canRead ? null : (
        <>
          <form
            className="toolbar"
            onSubmit={(event) => {
              event.preventDefault();
              setCursor("");
              setPrev([]);
              setQ(qInput.trim());
            }}
          >
            <div className="field">
              <label htmlFor="user-q">Search</label>
              <input
                id="user-q"
                value={qInput}
                autoComplete="off"
                spellCheck={false}
                onChange={(event) => setQInput(event.target.value)}
              />
            </div>
            <button type="submit" className="button-primary">Search</button>
            {createGate.ok ? (
              <Link className="button-link button-primary" to="/users/new">
                Create user
              </Link>
            ) : (
              <p>
                <span className="action-disabled">Create user</span>
                <span className="action-reason"> {createGate.reason}</span>
              </p>
            )}
          </form>
          {usersQuery.data === undefined ? (
            <QueryStatus result={usersQuery} missing="users" />
          ) : items.length === 0 ? (
            <p className="muted">{emptyListMessage("users", searching)}</p>
          ) : (
            <table>
              <caption>
                Directory users. Sort applies to the current page. Page size{" "}
                {DEFAULT_LIST_PAGE_SIZE}.
              </caption>
              <thead>
                <tr>
                  <SortHeader
                    label="ID"
                    column="id"
                    active={sortKey}
                    dir={sortDir}
                    onSort={(key) => {
                      setSortDir(nextSortDir(sortKey, key, sortDir));
                      setSortKey(key);
                    }}
                  />
                  <SortHeader
                    label="UID"
                    column="uid"
                    active={sortKey}
                    dir={sortDir}
                    onSort={(key) => {
                      setSortDir(nextSortDir(sortKey, key, sortDir));
                      setSortKey(key);
                    }}
                  />
                  <SortHeader
                    label="Enabled"
                    column="enabled"
                    active={sortKey}
                    dir={sortDir}
                    onSort={(key) => {
                      setSortDir(nextSortDir(sortKey, key, sortDir));
                      setSortKey(key);
                    }}
                  />
                </tr>
              </thead>
              <tbody>
                {items.map((user) => (
                  <UserRow key={user.id} user={user} />
                ))}
              </tbody>
            </table>
          )}
          <div className="pager">
            <button
              type="button"
              disabled={prev.length === 0}
              onClick={() => {
                const nextPrev = [...prev];
                const back = nextPrev.pop() ?? "";
                setPrev(nextPrev);
                setCursor(back);
              }}
            >
              Previous
            </button>
            <button
              type="button"
              disabled={usersQuery.data?.nextCursor === undefined || usersQuery.data.nextCursor === ""}
              onClick={() => {
                const next = usersQuery.data?.nextCursor;
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
          {isApiError(usersQuery.error) && !usersQuery.error.forbidden ? (
            <p>Could not refresh the user list.</p>
          ) : null}
        </>
      )}
    </ResourcePage>
  );
}

function UserRow({ user }: { user: User }) {
  return (
    <tr>
      <th scope="row">
        <Link to={`/users/${encodeURIComponent(user.id)}`}>{user.id}</Link>
      </th>
      <td>{user.uid}</td>
      <td>{user.enabled ? "Enabled" : "Disabled"}</td>
    </tr>
  );
}

function SortHeader({
  label,
  column,
  active,
  dir,
  onSort,
}: {
  label: string;
  column: UserSortKey;
  active: UserSortKey;
  dir: SortDir;
  onSort: (key: UserSortKey) => void;
}) {
  return (
    <th scope="col" aria-sort={ariaSort(active, column, dir)}>
      <button type="button" onClick={() => onSort(column)}>
        {label}
      </button>
    </th>
  );
}
