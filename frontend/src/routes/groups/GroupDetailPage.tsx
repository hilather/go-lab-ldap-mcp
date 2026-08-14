import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import {
  addGroupMembers,
  deleteGroup,
  getGroup,
  removeGroupMembers,
  replaceGroupMembers,
} from "../../api/groups";
import { isApiError } from "../../api/problem";
import type { MemberRef, MembershipSummary } from "../../api/types";
import { useSession } from "../../auth/SessionGate";
import {
  canSubmitMutation,
  cycleErrorMessage,
  emptyGroupExplanation,
  memberKey,
  membershipSummaryLabels,
  uniqueMembers,
  wouldEmptyGroup,
  type MemberChoice,
} from "../../lib/directory-model";
import { invalidateUsersAndGroups, queryKeys } from "../../lib/query";
import { hasScope, SCOPE_DIRECTORY_READ, SCOPE_DIRECTORY_WRITE } from "../../lib/session-model";
import { ConfirmDelete } from "../shared/ConfirmDelete";
import { ConflictRefresh } from "../shared/ConflictRefresh";
import { MemberSearch, toMemberRefs } from "../shared/MemberSearch";
import { QueryStatus, ResourcePage, ScopeNote } from "../shared/ResourcePage";

export function GroupDetailPage() {
  const params = useParams();
  const id = params.id ?? "";
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { session, canLogout } = useSession();
  const canRead = hasScope(session.scopes, SCOPE_DIRECTORY_READ);
  const writeGate = canSubmitMutation({
    hasWrite: hasScope(session.scopes, SCOPE_DIRECTORY_WRITE),
    csrfPresent: canLogout,
  });
  const [conflict, setConflict] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [notice, setNotice] = useState<string | undefined>();
  const [summary, setSummary] = useState<MembershipSummary | undefined>();
  const [selected, setSelected] = useState<MemberChoice[]>([]);
  const [removeIds, setRemoveIds] = useState<string[]>([]);

  const groupQuery = useQuery({
    queryKey: queryKeys.groups.detail(id),
    queryFn: () => getGroup(id),
    enabled: canRead && id !== "",
  });
  const group = groupQuery.data;

  const refresh = async (): Promise<void> => {
    setConflict(false);
    await queryClient.invalidateQueries({ queryKey: queryKeys.groups.detail(id) });
  };

  const runMembership = async (work: () => Promise<MembershipSummary>): Promise<void> => {
    setNotice(undefined);
    try {
      const result = await work();
      setSummary(result);
      setSelected([]);
      setRemoveIds([]);
      await invalidateUsersAndGroups(queryClient);
      await refresh();
    } catch (err) {
      if (isApiError(err) && err.revisionConflict) {
        setConflict(true);
        return;
      }
      if (isApiError(err) && err.cycle) {
        setNotice(cycleErrorMessage());
        return;
      }
      setNotice(isApiError(err) ? err.message : "The membership change was not applied.");
    }
  };

  return (
    <ResourcePage title={group === undefined ? "Group" : `Group ${group.id}`}>
      <p>
        <Link to="/groups">Back to groups</Link>
      </p>
      <ScopeNote scopes={session.scopes} required={SCOPE_DIRECTORY_READ} error={groupQuery.error} />
      {group === undefined ? (
        <QueryStatus result={groupQuery} missing="group" />
      ) : (
        <>
          {notice !== undefined ? (
            <p role="alert">{notice}</p>
          ) : null}
          <section aria-labelledby="group-overview-heading">
            <h2 id="group-overview-heading">Overview</h2>
            <dl>
              <div>
                <dt>ID</dt>
                <dd>
                  <code>{group.id}</code>
                </dd>
              </div>
              <div>
                <dt>DN</dt>
                <dd>
                  <code>{group.dn}</code>
                </dd>
              </div>
              <div>
                <dt>Revision</dt>
                <dd>
                  <code>{group.revision}</code>
                </dd>
              </div>
              <div>
                <dt>Direct members</dt>
                <dd>{group.members.length}</dd>
              </div>
            </dl>
            <p>
              Group attributes cannot be edited in v1. There is no PATCH for groups.
              Membership add, remove, and replace are the update path.
            </p>
          </section>

          <section aria-labelledby="group-members-heading">
            <h2 id="group-members-heading">Direct members</h2>
            {group.members.length === 0 ? (
              <p>{emptyGroupExplanation()}</p>
            ) : (
              <table>
                <caption>Direct members. Nested members are labeled by kind.</caption>
                <thead>
                  <tr>
                    <th scope="col">Kind</th>
                    <th scope="col">ID</th>
                    <th scope="col">DN</th>
                    <th scope="col">Remove</th>
                  </tr>
                </thead>
                <tbody>
                  {group.members.map((member) => {
                    const choice = asChoice(member);
                    const key = memberKey(choice);
                    return (
                      <tr key={key}>
                        <td>{choice.kind}</td>
                        <th scope="row">
                          <MemberLink member={choice} />
                        </th>
                        <td>
                          <code>{member.dn ?? ""}</code>
                        </td>
                        <td>
                          <label>
                            <input
                              type="checkbox"
                              disabled={!writeGate.ok}
                              checked={removeIds.includes(key)}
                              onChange={(event) => {
                                setRemoveIds((cur) =>
                                  event.target.checked ? [...cur, key] : cur.filter((item) => item !== key),
                                );
                              }}
                            />{" "}
                            Select
                          </label>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </section>

          {summary !== undefined ? <MembershipResult summary={summary} /> : null}

          <section aria-labelledby="group-membership-heading">
            <h2 id="group-membership-heading">Membership changes</h2>
            {!writeGate.ok ? <p>{writeGate.reason}</p> : null}
            <p>{emptyGroupExplanation()}</p>
            <MemberSearch
              legend="Members to add or use as a replacement set"
              selected={selected}
              onChange={setSelected}
              disabled={!writeGate.ok}
            />
            <div className="form-actions">
              <button
                type="button"
                disabled={!writeGate.ok || selected.length === 0}
                onClick={() =>
                  void runMembership(() => addGroupMembers(group.id, toMemberRefs(selected), group.revision))
                }
              >
                Add members
              </button>
              <button
                type="button"
                disabled={!writeGate.ok || removeIds.length === 0}
                onClick={() => {
                  if (wouldEmptyGroup(group.members.length, removeIds.length)) {
                    setNotice(emptyGroupExplanation());
                    return;
                  }
                  const refs = group.members.filter((member) => removeIds.includes(memberKey(asChoice(member))));
                  void runMembership(() => removeGroupMembers(group.id, refs, group.revision));
                }}
              >
                Remove selected
              </button>
              <button
                type="button"
                disabled={!writeGate.ok || selected.length === 0}
                onClick={() =>
                  void runMembership(() => replaceGroupMembers(group.id, toMemberRefs(selected), group.revision))
                }
              >
                Replace members
              </button>
              <button type="button" disabled={!writeGate.ok} onClick={() => setDeleteOpen(true)}>
                Delete group
              </button>
            </div>
          </section>

          <ConfirmDelete
            open={deleteOpen}
            resourceLabel="group"
            resourceId={group.id}
            disabled={!writeGate.ok}
            onDismiss={() => setDeleteOpen(false)}
            onConfirm={() => {
              void (async () => {
                try {
                  await deleteGroup(group.id, group.revision);
                  await invalidateUsersAndGroups(queryClient);
                  await navigate("/groups");
                } catch (err) {
                  setDeleteOpen(false);
                  if (isApiError(err) && err.revisionConflict) {
                    setConflict(true);
                    return;
                  }
                  setNotice(isApiError(err) ? err.message : "Group delete failed.");
                }
              })();
            }}
          />

          <ConflictRefresh
            open={conflict}
            onDismiss={() => setConflict(false)}
            onRefresh={() => {
              void refresh();
            }}
          />
        </>
      )}
    </ResourcePage>
  );
}

function MembershipResult({ summary }: { summary: MembershipSummary }) {
  const counts = membershipSummaryLabels(summary);
  return (
    <section aria-labelledby="membership-summary-heading">
      <h2 id="membership-summary-heading">Membership summary</h2>
      <p role="status">
        Added {counts.added}, removed {counts.removed}, unchanged {counts.unchanged}, rejected{" "}
        {counts.rejected}.
      </p>
      <MemberBucket title="Added" members={summary.added} />
      <MemberBucket title="Removed" members={summary.removed} />
      <MemberBucket title="Unchanged" members={summary.unchanged} />
      <MemberBucket title="Rejected" members={summary.rejected} />
    </section>
  );
}

function MemberBucket({ title, members }: { title: string; members: MemberRef[] }) {
  if (members.length === 0) {
    return (
      <p>
        {title}: none
      </p>
    );
  }
  return (
    <div>
      <h3>{title}</h3>
      <ul>
        {uniqueMembers(members.map(asChoice)).map((member) => (
          <li key={memberKey(member)}>
            {member.kind} <MemberLink member={member} />
          </li>
        ))}
      </ul>
    </div>
  );
}

function MemberLink({ member }: { member: MemberChoice }) {
  const href = member.kind === "user" ? `/users/${encodeURIComponent(member.id)}` : `/groups/${encodeURIComponent(member.id)}`;
  return <Link to={href}>{member.id}</Link>;
}

function asChoice(member: MemberRef): MemberChoice {
  return { kind: member.kind, id: member.id };
}
