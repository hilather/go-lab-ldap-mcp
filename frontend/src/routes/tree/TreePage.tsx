import { useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { createEntry, deleteEntry, getEntry, listSuffixes, listTree, moveEntry } from "../../api/entries";
import { isApiError } from "../../api/problem";
import type { TreeNode } from "../../api/types";
import { listUserGroups } from "../../api/users";
import { useSession } from "../../auth/SessionGate";
import { canSubmitMutation, exactIdConfirmed } from "../../lib/directory-model";
import { queryKeys } from "../../lib/query";
import { hasScope, SCOPE_DIRECTORY_READ, SCOPE_DIRECTORY_WRITE } from "../../lib/session-model";
import {
  canExpandTreeNode,
  childDN,
  displayMembershipLabel,
  entryKind,
  isProtectedTreeDN,
  isSensitiveAttr,
  membershipFromGroupEntry,
  parentDN,
  rdnOf,
  shouldShowNode,
  userIdFromEntry,
  writeOnlyPasswordRow,
  type EntryKind,
  type FilterableNode,
} from "../../lib/tree-model";
import { describedBy, ScopeNote } from "../shared/ResourcePage";
import { LiveRegion, SafeText } from "../shared/SafeText";

const CLASS_OPTIONS = [
  { value: "organizationalUnit", label: "organizationalUnit" },
  { value: "container", label: "container (stored as organizationalUnit)" },
  { value: "domain", label: "domain" },
] as const;

const TREE_FOOTNOTE =
  "Create users and groups on their own pages. The tree is for browsing and acting on a selected DN.";

const PROTECTED_REASON = "This managed suffix or people/groups container cannot be moved or deleted from the tree.";

export function TreePage() {
  const queryClient = useQueryClient();
  const { session, canLogout } = useSession();
  const canRead = hasScope(session.scopes, SCOPE_DIRECTORY_READ);
  const writeGate = canSubmitMutation({
    hasWrite: hasScope(session.scopes, SCOPE_DIRECTORY_WRITE),
    csrfPresent: canLogout,
  });
  const canWrite = writeGate.ok;
  const suffixes = useQuery({
    queryKey: queryKeys.directory.suffixes,
    queryFn: listSuffixes,
    enabled: canRead,
  });
  const [base, setBase] = useState("");
  const [selectedDN, setSelectedDN] = useState("");
  const [expanded, setExpanded] = useState<string[]>([]);
  const [filter, setFilter] = useState("");
  const [extraNodes, setExtraNodes] = useState<Record<string, TreeNode[]>>({});
  const [extraCursor, setExtraCursor] = useState<Record<string, string>>({});
  const [status, setStatus] = useState("");
  const [formError, setFormError] = useState("");
  const [createClass, setCreateClass] = useState<(typeof CLASS_OPTIONS)[number]["value"]>("organizationalUnit");
  const [createRDN, setCreateRDN] = useState("");
  const [moveTo, setMoveTo] = useState("");
  const [deleteConfirm, setDeleteConfirm] = useState("");
  const [deleteRecursive, setDeleteRecursive] = useState(false);

  const suffixList = suffixes.data?.all ?? [];
  const effectiveBase = base || suffixes.data?.primary || "";

  useEffect(() => {
    if (effectiveBase === "") {
      return;
    }
    setExpanded((prev) => (prev.includes(effectiveBase) ? prev : [...prev, effectiveBase]));
    setSelectedDN((prev) => (prev === "" ? effectiveBase : prev));
  }, [effectiveBase]);

  useEffect(() => {
    setMoveTo(selectedDN);
    setDeleteConfirm("");
    setDeleteRecursive(false);
  }, [selectedDN]);

  const treeQueries = useQueries({
    queries: expanded.map((dn) => ({
      queryKey: queryKeys.directory.tree(dn, ""),
      queryFn: () => listTree(dn),
      enabled: canRead && dn !== "",
    })),
  });

  const childrenByBase = useMemo(() => {
    const map = new Map<string, TreeNode[]>();
    for (const result of treeQueries) {
      if (result.data === undefined) {
        continue;
      }
      const more = extraNodes[result.data.base] ?? [];
      map.set(result.data.base, [...result.data.nodes, ...more]);
    }
    return map;
  }, [extraNodes, treeQueries]);

  const filterChildren = useMemo(() => {
    const map = new Map<string, FilterableNode[]>();
    for (const [dn, nodes] of childrenByBase) {
      map.set(dn, nodes);
    }
    return map;
  }, [childrenByBase]);

  const entry = useQuery({
    queryKey: queryKeys.directory.entry(selectedDN),
    queryFn: () => getEntry(selectedDN),
    enabled: canRead && selectedDN !== "",
  });
  const selectedIsSuffix = suffixList.some((dn) => dn === selectedDN);
  const kind: EntryKind | undefined =
    entry.data === undefined
      ? undefined
      : entryKind(entry.data.objectClasses, { isSuffix: selectedIsSuffix });
  const userId = entry.data !== undefined && kind === "user" ? userIdFromEntry(entry.data) : undefined;
  const userGroups = useQuery({
    queryKey: queryKeys.users.groups(userId ?? ""),
    queryFn: () => listUserGroups(userId ?? ""),
    enabled: canRead && userId !== undefined && userId !== "",
  });

  const protectedDN = isProtectedTreeDN(selectedDN, suffixList);
  const mutateReason = !canWrite ? writeGate.reason : protectedDN ? PROTECTED_REASON : "";
  const createReason = canWrite ? "" : writeGate.reason;

  const resetTreePages = (dn: string): void => {
    setExtraNodes((prev) => {
      const next = { ...prev };
      delete next[dn];
      return next;
    });
    setExtraCursor((prev) => {
      const next = { ...prev };
      delete next[dn];
      return next;
    });
  };

  const refresh = async (bases: readonly string[]): Promise<void> => {
    await queryClient.invalidateQueries({ queryKey: queryKeys.directory.suffixes });
    for (const dn of bases) {
      resetTreePages(dn);
      await queryClient.invalidateQueries({ queryKey: queryKeys.directory.tree(dn, "") });
    }
    if (selectedDN !== "") {
      await queryClient.invalidateQueries({ queryKey: queryKeys.directory.entry(selectedDN) });
    }
  };

  const changeSuffix = (next: string): void => {
    setBase(next);
    setSelectedDN(next);
    setExpanded([next]);
    setFilter("");
    setExtraNodes({});
    setExtraCursor({});
    setStatus("");
    setFormError("");
  };

  const toggleExpanded = (dn: string): void => {
    setExpanded((prev) => (prev.includes(dn) ? prev.filter((item) => item !== dn) : [...prev, dn]));
  };

  const nextCursorFor = (dn: string): string | undefined => {
    const extra = extraCursor[dn];
    if (extra !== undefined) {
      return extra === "" ? undefined : extra;
    }
    const page = treeQueries.find((result) => result.data?.base === dn)?.data;
    const cursor = page?.nextCursor;
    return cursor !== undefined && cursor !== "" ? cursor : undefined;
  };

  const loadMore = async (dn: string): Promise<void> => {
    const cursor = nextCursorFor(dn);
    if (cursor === undefined) {
      return;
    }
    try {
      const page = await listTree(dn, cursor);
      setExtraNodes((prev) => ({ ...prev, [dn]: [...(prev[dn] ?? []), ...page.nodes] }));
      setExtraCursor((prev) => ({ ...prev, [dn]: page.nextCursor ?? "" }));
    } catch (err) {
      setFormError(isApiError(err) ? err.message : "Could not load more entries.");
    }
  };

  const pendingBase = (dn: string): boolean => {
    const idx = expanded.indexOf(dn);
    if (idx === -1) {
      return false;
    }
    const result = treeQueries[idx];
    return result?.isPending === true && childrenByBase.get(dn) === undefined;
  };

  const treeError = (dn: string): unknown => {
    const idx = expanded.indexOf(dn);
    if (idx === -1) {
      return undefined;
    }
    return treeQueries[idx]?.error;
  };

  return (
    <main id="main" className="directory-workspace">
      <ScopeNote scopes={session.scopes} required={SCOPE_DIRECTORY_READ} error={suffixes.error} />
      <LiveRegion message={status} />
      {formError !== "" ? (
        <p role="alert" className="field-error">
          {formError}
        </p>
      ) : null}

      <div className="directory-split">
        <section className="tree-pane" aria-labelledby="tree-pane-heading">
          <p className="tree-eyebrow" id="tree-pane-heading">
            TREE
          </p>
          <div className="field">
            <label htmlFor="tree-filter">Filter RDN or DN</label>
            <input
              id="tree-filter"
              type="text"
              autoComplete="off"
              spellCheck={false}
              placeholder="Filter RDN or DN"
              value={filter}
              disabled={!canRead}
              onChange={(event) => setFilter(event.target.value)}
            />
            <p className="field-hint">Filters already-loaded nodes. Descendants that have not been expanded are hidden.</p>
          </div>
          {suffixList.length > 1 ? (
            <div className="field">
              <label htmlFor="tree-suffix">Managed suffix</label>
              <select
                id="tree-suffix"
                value={effectiveBase}
                disabled={!canRead}
                onChange={(event) => changeSuffix(event.target.value)}
              >
                {suffixList.map((dn) => (
                  <option key={dn} value={dn}>
                    {dn}
                  </option>
                ))}
              </select>
            </div>
          ) : null}
          {!canRead ? null : effectiveBase === "" && suffixes.isPending ? (
            <p>Loading tree…</p>
          ) : effectiveBase === "" ? (
            <p>No managed suffix is available.</p>
          ) : (
            <ul className="tree-list">
              <TreeBranch
                node={{
                  dn: effectiveBase,
                  rdn: rdnOf(effectiveBase),
                  objectClasses: ["domain"],
                  hasChildren: true,
                }}
                kind="suffix"
                selectedDN={selectedDN}
                expanded={expanded}
                filter={filter}
                childrenByBase={childrenByBase}
                filterChildren={filterChildren}
                pendingBase={pendingBase}
                treeError={treeError}
                nextCursorFor={nextCursorFor}
                onSelect={setSelectedDN}
                onToggle={toggleExpanded}
                onLoadMore={(dn) => void loadMore(dn)}
              />
            </ul>
          )}
        </section>

        <section className="inspector" aria-labelledby="inspector-heading">
          {selectedDN === "" ? (
            <h1 id="inspector-heading">Directory</h1>
          ) : (
            <>
              <h1 id="inspector-heading">
                <SafeText value={rdnOf(selectedDN)} />
              </h1>
              <p className="inspector-dn">
                <SafeText value={selectedDN} />
              </p>
              <div className="inspector-actions">
                <button type="button" disabled={!canWrite || protectedDN} onClick={() => document.getElementById("tree-move-to")?.focus()}>
                  Move
                </button>
                <button
                  type="button"
                  className="button-danger"
                  disabled={!canWrite || protectedDN}
                  onClick={() => document.getElementById("tree-delete-confirm")?.focus()}
                >
                  Delete
                </button>
                <button
                  type="button"
                  className="button-primary"
                  disabled={!canWrite}
                  onClick={() => document.getElementById("tree-create-rdn")?.focus()}
                >
                  Create child
                </button>
              </div>
              {mutateReason !== "" ? <p className="field-hint">{mutateReason}</p> : null}
              {createReason !== "" && mutateReason !== createReason ? <p className="field-hint">{createReason}</p> : null}

              {entry.isPending ? <p>Loading entry…</p> : null}
              {entry.error !== null && entry.error !== undefined ? (
                <p>Could not load this entry.</p>
              ) : null}

              {entry.data !== undefined && kind !== undefined ? (
                <>
                  <section className="inspector-card" aria-labelledby="inspector-attrs-heading">
                    <h2 id="inspector-attrs-heading">Attributes</h2>
                    <AttributeList entry={entry.data} kind={kind} />
                  </section>
                  <section className="inspector-card" aria-labelledby="inspector-membership-heading">
                    <h2 id="inspector-membership-heading">Membership</h2>
                    <MembershipList
                      kind={kind}
                      groupDNs={kind === "group" ? membershipFromGroupEntry(entry.data) : []}
                      userGroups={userGroups.data?.items ?? []}
                      groupsPending={userGroups.isPending}
                      groupsError={userGroups.error}
                    />
                  </section>
                </>
              ) : null}

              <section className="inspector-card" aria-labelledby="tree-create-heading">
                <h2 id="tree-create-heading">Create child</h2>
                {!canWrite ? <p>{writeGate.reason}</p> : null}
                <form
                  onSubmit={async (event) => {
                    event.preventDefault();
                    if (!canWrite || selectedDN === "") {
                      return;
                    }
                    setFormError("");
                    try {
                      const dn = childDN(createRDN, selectedDN);
                      const created = await createEntry({ dn, objectClasses: [createClass] });
                      setCreateRDN("");
                      setStatus(`Created ${created.dn}`);
                      setExpanded((prev) => (prev.includes(selectedDN) ? prev : [...prev, selectedDN]));
                      await refresh([selectedDN]);
                    } catch (err) {
                      setFormError(isApiError(err) ? err.message : "Entry create failed.");
                    }
                  }}
                >
                  <div className="field">
                    <label htmlFor="tree-create-class">Object class</label>
                    <select
                      id="tree-create-class"
                      value={createClass}
                      onChange={(event) => setCreateClass(event.target.value as typeof createClass)}
                    >
                      {CLASS_OPTIONS.map((opt) => (
                        <option key={opt.value} value={opt.value}>
                          {opt.label}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="field">
                    <label htmlFor="tree-create-rdn">RDN</label>
                    <input
                      id="tree-create-rdn"
                      autoComplete="off"
                      spellCheck={false}
                      value={createRDN}
                      onChange={(event) => setCreateRDN(event.target.value)}
                      aria-required="true"
                      aria-describedby={describedBy(["tree-create-hint"])}
                    />
                    <p id="tree-create-hint" className="field-hint">
                      Type an RDN such as ou=labtree, or a full DN that already contains a comma.
                    </p>
                  </div>
                  <button type="submit" className="button-primary" disabled={!canWrite || selectedDN === ""}>
                    Create child
                  </button>
                </form>
              </section>

              <section className="inspector-card" aria-labelledby="tree-move-heading">
                <h2 id="tree-move-heading">Move or rename</h2>
                <form
                  onSubmit={async (event) => {
                    event.preventDefault();
                    if (!canWrite || selectedDN === "" || protectedDN) {
                      return;
                    }
                    setFormError("");
                    try {
                      const live = await getEntry(selectedDN);
                      const moved = await moveEntry(
                        { dn: selectedDN, newDN: moveTo.trim(), deleteOldRdn: true },
                        live.revision,
                      );
                      const oldParent = parentDN(selectedDN);
                      const newParent = parentDN(moved.dn);
                      setStatus(`Moved to ${moved.dn}`);
                      setSelectedDN(moved.dn);
                      setMoveTo(moved.dn);
                      await refresh([oldParent, newParent]);
                    } catch (err) {
                      setFormError(isApiError(err) ? err.message : "Move failed.");
                    }
                  }}
                >
                  <div className="field">
                    <label htmlFor="tree-move-to">New DN</label>
                    <input
                      id="tree-move-to"
                      autoComplete="off"
                      spellCheck={false}
                      value={moveTo}
                      disabled={!canWrite || protectedDN}
                      onChange={(event) => setMoveTo(event.target.value)}
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={!canWrite || protectedDN || selectedDN === "" || moveTo.trim() === "" || moveTo.trim() === selectedDN}
                  >
                    Move entry
                  </button>
                </form>
              </section>

              <section className="inspector-card" aria-labelledby="tree-delete-heading">
                <h2 id="tree-delete-heading">Delete entry</h2>
                <form
                  onSubmit={async (event) => {
                    event.preventDefault();
                    if (!canWrite || selectedDN === "" || protectedDN) {
                      return;
                    }
                    if (!exactIdConfirmed(selectedDN, deleteConfirm.trim())) {
                      setFormError("Type the exact DN to confirm delete.");
                      return;
                    }
                    setFormError("");
                    try {
                      const live = await getEntry(selectedDN);
                      await deleteEntry(selectedDN, live.revision, deleteRecursive);
                      const next = parentDN(selectedDN);
                      setStatus("Deleted entry.");
                      setSelectedDN(next === selectedDN ? effectiveBase : next);
                      setDeleteConfirm("");
                      setDeleteRecursive(false);
                      await refresh([next]);
                    } catch (err) {
                      setFormError(isApiError(err) ? err.message : "Delete failed.");
                    }
                  }}
                >
                  <div className="field">
                    <label htmlFor="tree-delete-confirm">Type the exact DN to confirm</label>
                    <input
                      id="tree-delete-confirm"
                      autoComplete="off"
                      spellCheck={false}
                      value={deleteConfirm}
                      disabled={!canWrite || protectedDN}
                      onChange={(event) => setDeleteConfirm(event.target.value)}
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
                        disabled={!canWrite || protectedDN}
                        onChange={(event) => setDeleteRecursive(event.target.checked)}
                      />{" "}
                      Recursive
                    </label>
                  </div>
                  <button type="submit" className="button-danger" disabled={!canWrite || protectedDN || selectedDN === ""}>
                    Delete entry
                  </button>
                </form>
              </section>
            </>
          )}
        </section>
      </div>
      <p className="directory-footnote">{TREE_FOOTNOTE}</p>
    </main>
  );
}

function AttributeList({
  entry,
  kind,
}: {
  entry: { attributes: readonly { name: string; value: string }[] };
  kind: EntryKind;
}) {
  const rows = entry.attributes.filter((attr) => !isSensitiveAttr(attr.name));
  const password = writeOnlyPasswordRow(kind);
  const shown = password === undefined ? rows : [...rows, password];
  if (shown.length === 0) {
    return <p className="muted">No attributes returned for this entry.</p>;
  }
  return (
    <dl>
      {shown.map((attr) => (
        <div key={`${attr.name}:${attr.value}`}>
          <dt>
            <SafeText value={attr.name} />
          </dt>
          <dd>
            <SafeText value={attr.value} />
            {attr.name === "userPassword" ? <p className="field-hint">not returned by the API</p> : null}
          </dd>
        </div>
      ))}
    </dl>
  );
}

function MembershipList({
  kind,
  groupDNs,
  userGroups,
  groupsPending,
  groupsError,
}: {
  kind: EntryKind;
  groupDNs: readonly string[];
  userGroups: readonly { id: string; dn?: string }[];
  groupsPending: boolean;
  groupsError: unknown;
}) {
  if (kind === "user") {
    if (groupsPending) {
      return <p>Loading membership…</p>;
    }
    if (groupsError !== null && groupsError !== undefined) {
      return <p>Could not load membership.</p>;
    }
    if (userGroups.length === 0) {
      return <p className="muted">None</p>;
    }
    return (
      <ul className="membership-list">
        {userGroups.map((group) => {
          const label = displayMembershipLabel(group);
          return (
            <li key={group.id}>
              <span className="membership-pill" title={group.dn ?? label}>
                <SafeText value={label} />
              </span>
            </li>
          );
        })}
      </ul>
    );
  }
  if (kind === "group") {
    if (groupDNs.length === 0) {
      return <p className="muted">None</p>;
    }
    return (
      <ul className="membership-list">
        {groupDNs.map((dn) => (
          <li key={dn}>
            <span className="membership-pill" title={dn}>
              <SafeText value={rdnOf(dn)} />
            </span>
          </li>
        ))}
      </ul>
    );
  }
  return <p className="muted">None</p>;
}

function TreeBranch({
  node,
  kind,
  selectedDN,
  expanded,
  filter,
  childrenByBase,
  filterChildren,
  pendingBase,
  treeError,
  nextCursorFor,
  onSelect,
  onToggle,
  onLoadMore,
}: {
  node: TreeNode;
  kind: EntryKind;
  selectedDN: string;
  expanded: readonly string[];
  filter: string;
  childrenByBase: ReadonlyMap<string, readonly TreeNode[]>;
  filterChildren: ReadonlyMap<string, readonly FilterableNode[]>;
  pendingBase: (dn: string) => boolean;
  treeError: (dn: string) => unknown;
  nextCursorFor: (dn: string) => string | undefined;
  onSelect: (dn: string) => void;
  onToggle: (dn: string) => void;
  onLoadMore: (dn: string) => void;
}) {
  if (!shouldShowNode(node, filter, filterChildren)) {
    return null;
  }
  const kids = childrenByBase.get(node.dn) ?? [];
  const isExpanded = expanded.includes(node.dn);
  const canExpand = canExpandTreeNode({
    hasChildren: node.hasChildren,
    loaded: childrenByBase.has(node.dn),
    childCount: kids.length,
    kind,
  });
  const err = treeError(node.dn);
  const more = nextCursorFor(node.dn);
  return (
    <li>
      <div className="tree-row">
        {canExpand ? (
          <button
            type="button"
            className="tree-twistie"
            aria-expanded={isExpanded}
            aria-label={isExpanded ? `Collapse ${node.rdn}` : `Expand ${node.rdn}`}
            onClick={() => onToggle(node.dn)}
          >
            {isExpanded ? "▾" : "▸"}
          </button>
        ) : (
          <span className="tree-twistie-spacer" />
        )}
        <button
          type="button"
          className={selectedDN === node.dn ? "tree-node-label is-selected" : "tree-node-label"}
          aria-current={selectedDN === node.dn ? "true" : undefined}
          aria-label={node.rdn}
          onClick={() => onSelect(node.dn)}
        >
          <SafeText value={node.rdn || node.dn} />
          <span className="tree-kind" aria-hidden="true">
            {kind}
          </span>
        </button>
      </div>
      {isExpanded ? (
        <ul className="tree-children">
          {pendingBase(node.dn) ? (
            <li>
              <p>Loading tree…</p>
            </li>
          ) : null}
          {err !== undefined && err !== null ? (
            <li>
              <p>Could not load children.</p>
            </li>
          ) : null}
          {kids.map((child) => (
            <TreeBranch
              key={child.dn}
              node={child}
              kind={entryKind(child.objectClasses)}
              selectedDN={selectedDN}
              expanded={expanded}
              filter={filter}
              childrenByBase={childrenByBase}
              filterChildren={filterChildren}
              pendingBase={pendingBase}
              treeError={treeError}
              nextCursorFor={nextCursorFor}
              onSelect={onSelect}
              onToggle={onToggle}
              onLoadMore={onLoadMore}
            />
          ))}
          {more !== undefined ? (
            <li>
              <button type="button" onClick={() => onLoadMore(node.dn)}>
                Load more
              </button>
            </li>
          ) : null}
        </ul>
      ) : null}
    </li>
  );
}
