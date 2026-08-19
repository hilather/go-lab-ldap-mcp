import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { createEntry, deleteEntry, getEntry, listSuffixes, listTree, moveEntry } from "../../api/entries";
import { createGroup } from "../../api/groups";
import { isApiError } from "../../api/problem";
import { createUser } from "../../api/users";
import { useSession } from "../../auth/SessionGate";
import { queryKeys } from "../../lib/query";
import { hasScope, SCOPE_DIRECTORY_READ, SCOPE_DIRECTORY_WRITE } from "../../lib/session-model";
import { describedBy, ResourcePage, ScopeNote } from "../shared/ResourcePage";
import { LiveRegion, SafeText } from "../shared/SafeText";

const CLASS_OPTIONS = [
  { value: "organizationalUnit", label: "organizationalUnit" },
  { value: "container", label: "container (stored as organizationalUnit)" },
  { value: "domain", label: "domain" },
] as const;

export function TreePage() {
  const queryClient = useQueryClient();
  const { session, canLogout } = useSession();
  const canRead = hasScope(session.scopes, SCOPE_DIRECTORY_READ);
  const canWrite = hasScope(session.scopes, SCOPE_DIRECTORY_WRITE) && canLogout;
  const suffixes = useQuery({
    queryKey: queryKeys.directory.suffixes,
    queryFn: listSuffixes,
    enabled: canRead,
  });
  const [base, setBase] = useState("");
  const [status, setStatus] = useState("");
  const [formError, setFormError] = useState("");
  const effectiveBase = base || suffixes.data?.primary || "";
  const tree = useQuery({
    queryKey: queryKeys.directory.tree(effectiveBase, ""),
    queryFn: () => listTree(effectiveBase),
    enabled: canRead && effectiveBase !== "",
  });

  const [createClass, setCreateClass] = useState<(typeof CLASS_OPTIONS)[number]["value"]>("organizationalUnit");
  const [createDN, setCreateDN] = useState("");
  const [userID, setUserID] = useState("");
  const [userDN, setUserDN] = useState("");
  const [userPassword, setUserPassword] = useState("");
  const [groupID, setGroupID] = useState("");
  const [groupDN, setGroupDN] = useState("");
  const [groupMember, setGroupMember] = useState("");
  const [moveFrom, setMoveFrom] = useState("");
  const [moveTo, setMoveTo] = useState("");
  const [deleteDN, setDeleteDN] = useState("");
  const [deleteConfirm, setDeleteConfirm] = useState("");
  const [deleteRecursive, setDeleteRecursive] = useState(false);

  const refresh = async (): Promise<void> => {
    await queryClient.invalidateQueries({ queryKey: queryKeys.directory.suffixes });
    await queryClient.invalidateQueries({ queryKey: [...queryKeys.directory.all, "tree"] });
  };

  return (
    <ResourcePage title="Directory tree">
      <ScopeNote scopes={session.scopes} required={SCOPE_DIRECTORY_READ} error={suffixes.error ?? tree.error} />
      <p>
        Browse compiled managed suffixes and create allowlisted entries. Extra regional domains belong in{" "}
        <code>additionalSuffixes</code>. This is multiple suffixes in one lab, not an AD forest or trust.
      </p>
      <LiveRegion message={status} />
      {formError !== "" ? (
        <p role="alert" className="field-error">
          {formError}
        </p>
      ) : null}

      <div className="field">
        <label htmlFor="tree-suffix">Managed suffix</label>
        <select
          id="tree-suffix"
          value={effectiveBase}
          disabled={!canRead}
          onChange={(event) => {
            setBase(event.target.value);
            setStatus("");
          }}
        >
          {(suffixes.data?.all ?? []).map((dn) => (
            <option key={dn} value={dn}>
              {dn}
            </option>
          ))}
        </select>
      </div>

      <section aria-labelledby="tree-browse-heading">
        <h2 id="tree-browse-heading">Children of {effectiveBase || "…"}</h2>
        {!canRead ? null : tree.isPending ? (
          <p role="status">Loading tree…</p>
        ) : (
          <ul>
            {(tree.data?.nodes ?? []).map((node) => (
              <li key={node.dn}>
                <button type="button" onClick={() => setBase(node.dn)}>
                  <SafeText value={node.rdn || node.dn} />
                </button>
                {node.hasChildren ? " (has children)" : ""}
              </li>
            ))}
          </ul>
        )}
        {effectiveBase !== "" && effectiveBase !== suffixes.data?.primary ? (
          <button type="button" onClick={() => setBase(parentHint(effectiveBase))}>
            Up one level
          </button>
        ) : null}
      </section>

      <section aria-labelledby="tree-create-heading">
        <h2 id="tree-create-heading">Create OU, domain, or container</h2>
        {!canWrite ? <p>Requires scope directory:write.</p> : null}
        <form
          onSubmit={async (event) => {
            event.preventDefault();
            if (!canWrite) {
              return;
            }
            setFormError("");
            try {
              const created = await createEntry({ dn: createDN.trim(), objectClasses: [createClass] });
              setCreateDN("");
              setStatus(`Created ${created.dn}`);
              await refresh();
            } catch (err) {
              setFormError(isApiError(err) ? err.message : "Entry create failed.");
            }
          }}
        >
          <div className="field">
            <label htmlFor="tree-create-class">Object class</label>
            <select id="tree-create-class" value={createClass} onChange={(e) => setCreateClass(e.target.value as typeof createClass)}>
              {CLASS_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="tree-create-dn">DN</label>
            <input
              id="tree-create-dn"
              autoComplete="off"
              spellCheck={false}
              value={createDN}
              onChange={(e) => setCreateDN(e.target.value)}
              aria-required="true"
            />
          </div>
          <button type="submit" disabled={!canWrite}>
            Create entry
          </button>
        </form>
      </section>

      <section aria-labelledby="tree-user-heading">
        <h2 id="tree-user-heading">Create user at exact DN</h2>
        <form
          onSubmit={async (event) => {
            event.preventDefault();
            if (!canWrite) {
              return;
            }
            setFormError("");
            try {
              const created = await createUser({
                id: userID.trim(),
                password: userPassword,
                dn: userDN.trim(),
              });
              setUserPassword("");
              setStatus(`Created user ${created.id} at ${created.dn}`);
              await refresh();
            } catch (err) {
              setUserPassword("");
              setFormError(isApiError(err) ? err.message : "User create failed.");
            }
          }}
        >
          <div className="field">
            <label htmlFor="tree-user-id">User ID</label>
            <input id="tree-user-id" autoComplete="off" spellCheck={false} value={userID} onChange={(e) => setUserID(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="tree-user-dn">User DN</label>
            <input id="tree-user-dn" autoComplete="off" spellCheck={false} value={userDN} onChange={(e) => setUserDN(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="tree-user-password">Password</label>
            <input
              id="tree-user-password"
              type="password"
              autoComplete="new-password"
              value={userPassword}
              onChange={(e) => setUserPassword(e.target.value)}
            />
          </div>
          <button type="submit" disabled={!canWrite}>
            Create user at DN
          </button>
        </form>
      </section>

      <section aria-labelledby="tree-group-heading">
        <h2 id="tree-group-heading">Create group at exact DN</h2>
        <form
          onSubmit={async (event) => {
            event.preventDefault();
            if (!canWrite) {
              return;
            }
            setFormError("");
            try {
              const created = await createGroup({
                id: groupID.trim(),
                members: [{ kind: "user", id: groupMember.trim() }],
                ...(groupDN.trim() !== "" ? { dn: groupDN.trim() } : {}),
              });
              setStatus(`Created group ${created.id} at ${created.dn}`);
              await refresh();
            } catch (err) {
              setFormError(isApiError(err) ? err.message : "Group create failed.");
            }
          }}
        >
          <div className="field">
            <label htmlFor="tree-group-id">Group ID</label>
            <input id="tree-group-id" autoComplete="off" spellCheck={false} value={groupID} onChange={(e) => setGroupID(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="tree-group-dn">Group DN (optional)</label>
            <input id="tree-group-dn" autoComplete="off" spellCheck={false} value={groupDN} onChange={(e) => setGroupDN(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="tree-group-member">Member user ID</label>
            <input
              id="tree-group-member"
              autoComplete="off"
              spellCheck={false}
              value={groupMember}
              onChange={(e) => setGroupMember(e.target.value)}
            />
          </div>
          <button type="submit" disabled={!canWrite}>
            Create group at DN
          </button>
        </form>
      </section>

      <section aria-labelledby="tree-move-heading">
        <h2 id="tree-move-heading">Move or rename</h2>
        <form
          onSubmit={async (event) => {
            event.preventDefault();
            if (!canWrite) {
              return;
            }
            setFormError("");
            try {
              const live = await getEntry(moveFrom.trim());
              const moved = await moveEntry({ dn: moveFrom.trim(), newDN: moveTo.trim(), deleteOldRdn: true }, live.revision);
              setStatus(`Moved to ${moved.dn}`);
              await refresh();
            } catch (err) {
              setFormError(isApiError(err) ? err.message : "Move failed.");
            }
          }}
        >
          <div className="field">
            <label htmlFor="tree-move-from">Current DN</label>
            <input id="tree-move-from" autoComplete="off" spellCheck={false} value={moveFrom} onChange={(e) => setMoveFrom(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="tree-move-to">New DN</label>
            <input id="tree-move-to" autoComplete="off" spellCheck={false} value={moveTo} onChange={(e) => setMoveTo(e.target.value)} />
          </div>
          <button type="submit" disabled={!canWrite}>
            Move entry
          </button>
        </form>
      </section>

      <section aria-labelledby="tree-delete-heading">
        <h2 id="tree-delete-heading">Delete entry</h2>
        <form
          onSubmit={async (event) => {
            event.preventDefault();
            if (!canWrite) {
              return;
            }
            if (deleteConfirm.trim() !== deleteDN.trim()) {
              setFormError("Type the exact DN to confirm delete.");
              return;
            }
            setFormError("");
            try {
              const live = await getEntry(deleteDN.trim());
              await deleteEntry(deleteDN.trim(), live.revision, deleteRecursive);
              setDeleteDN("");
              setDeleteConfirm("");
              setStatus("Deleted entry.");
              await refresh();
            } catch (err) {
              setFormError(isApiError(err) ? err.message : "Delete failed.");
            }
          }}
        >
          <div className="field">
            <label htmlFor="tree-delete-dn">DN</label>
            <input id="tree-delete-dn" autoComplete="off" spellCheck={false} value={deleteDN} onChange={(e) => setDeleteDN(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="tree-delete-confirm">Type the exact DN to confirm</label>
            <input
              id="tree-delete-confirm"
              autoComplete="off"
              spellCheck={false}
              value={deleteConfirm}
              onChange={(e) => setDeleteConfirm(e.target.value)}
              aria-describedby={describedBy(["tree-delete-hint"])}
            />
            <p id="tree-delete-hint" className="field-hint">
              Destructive. Non-empty containers also need recursive delete.
            </p>
          </div>
          <div className="field">
            <label htmlFor="tree-delete-recursive">
              <input
                id="tree-delete-recursive"
                type="checkbox"
                checked={deleteRecursive}
                onChange={(e) => setDeleteRecursive(e.target.checked)}
              />{" "}
              Recursive
            </label>
          </div>
          <button type="submit" disabled={!canWrite}>
            Delete entry
          </button>
        </form>
      </section>
    </ResourcePage>
  );
}

function parentHint(dn: string): string {
  const i = dn.indexOf(",");
  return i === -1 ? dn : dn.slice(i + 1);
}
