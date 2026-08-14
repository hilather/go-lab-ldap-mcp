import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link } from "react-router";
import { listGroups } from "../../api/groups";
import { isApiError } from "../../api/problem";
import type { Group } from "../../api/types";
import { useSession } from "../../auth/SessionGate";
import {
  ariaSort,
  canSubmitMutation,
  DEFAULT_LIST_PAGE_SIZE,
  emptyGroupExplanation,
  emptyListMessage,
  listQuery,
  nextSortDir,
  sortGroups,
  type SortDir,
} from "../../lib/directory-model";
import { queryKeys } from "../../lib/query";
import { hasScope, SCOPE_DIRECTORY_READ, SCOPE_DIRECTORY_WRITE } from "../../lib/session-model";
import { QueryStatus, ResourcePage, ScopeNote } from "../shared/ResourcePage";

type GroupSortKey = "id" | "memberCount";

export function GroupListPage() {
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
  const [sortKey, setSortKey] = useState<GroupSortKey>("id");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const query = listQuery({ pageSize: DEFAULT_LIST_PAGE_SIZE, q, cursor });
  const groupsQuery = useQuery({
    queryKey: queryKeys.groups.list(query),
    queryFn: () => listGroups(query),
    enabled: canRead,
  });
  const items = useMemo(() => {
    const rows = (groupsQuery.data?.items ?? []).map((group) => ({
      ...group,
      memberCount: group.members.length,
    }));
    return sortGroups(rows, sortKey, sortDir);
  }, [groupsQuery.data?.items, sortKey, sortDir]);
  const searching = q.trim() !== "";

  return (
    <ResourcePage title="Groups">
      <ScopeNote scopes={session.scopes} required={SCOPE_DIRECTORY_READ} error={groupsQuery.error} />
      {!canRead ? null : (
        <>
          <p>{emptyGroupExplanation()}</p>
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
              <label htmlFor="group-q">Search</label>
              <input
                id="group-q"
                value={qInput}
                autoComplete="off"
                spellCheck={false}
                onChange={(event) => setQInput(event.target.value)}
              />
            </div>
            <button type="submit">Search</button>
            {createGate.ok ? (
              <Link className="button-link" to="/groups/new">
                Create group
              </Link>
            ) : (
              <p>
                <span className="action-disabled">Create group</span>
                <span className="action-reason"> {createGate.reason}</span>
              </p>
            )}
          </form>
          {groupsQuery.data === undefined ? (
            <QueryStatus result={groupsQuery} missing="groups" />
          ) : items.length === 0 ? (
            <p>{emptyListMessage("groups", searching)}</p>
          ) : (
            <table>
              <caption>
                Directory groups. Sort applies to the current page. Page size{" "}
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
                    label="Members"
                    column="memberCount"
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
                {items.map((group) => (
                  <GroupRow key={group.id} group={group} />
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
              disabled={groupsQuery.data?.nextCursor === undefined || groupsQuery.data.nextCursor === ""}
              onClick={() => {
                const next = groupsQuery.data?.nextCursor;
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
          {isApiError(groupsQuery.error) && !groupsQuery.error.forbidden ? (
            <p>Could not refresh the group list.</p>
          ) : null}
        </>
      )}
    </ResourcePage>
  );
}

function GroupRow({ group }: { group: Group & { memberCount: number } }) {
  return (
    <tr>
      <th scope="row">
        <Link to={`/groups/${encodeURIComponent(group.id)}`}>{group.id}</Link>
      </th>
      <td>{group.memberCount}</td>
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
  column: GroupSortKey;
  active: GroupSortKey;
  dir: SortDir;
  onSort: (key: GroupSortKey) => void;
}) {
  return (
    <th scope="col" aria-sort={ariaSort(active, column, dir)}>
      <button type="button" onClick={() => onSort(column)}>
        {label}
      </button>
    </th>
  );
}
