import { useState } from "react";
import { listGroups } from "../../api/groups";
import { isApiError } from "../../api/problem";
import type { MemberRef } from "../../api/types";
import { listUsers } from "../../api/users";
import {
  MEMBER_SEARCH_PAGE_SIZE,
  memberKey,
  uniqueMembers,
  type MemberChoice,
  type MemberKind,
} from "../../lib/directory-model";
import { describedBy, FormError } from "./ResourcePage";

export function MemberSearch({
  selected,
  onChange,
  error,
  disabled,
  legend,
}: {
  selected: MemberChoice[];
  onChange: (members: MemberChoice[]) => void;
  error?: string | undefined;
  disabled: boolean;
  legend: string;
}) {
  const [kind, setKind] = useState<MemberKind>("user");
  const [q, setQ] = useState("");
  const [results, setResults] = useState<MemberChoice[]>([]);
  const [status, setStatus] = useState<string | undefined>();
  const [searching, setSearching] = useState(false);

  const runSearch = async (): Promise<void> => {
    setSearching(true);
    setStatus(undefined);
    try {
      const found = await searchMembers(kind, q);
      setResults(found);
      setStatus(found.length === 0 ? "No matching directory members." : undefined);
    } catch (err) {
      setResults([]);
      setStatus(isApiError(err) ? err.message : "Member search failed.");
    } finally {
      setSearching(false);
    }
  };

  return (
    <fieldset className="member-search" disabled={disabled}>
      <legend>{legend}</legend>
      <p>
        Search is bounded to {MEMBER_SEARCH_PAGE_SIZE} server results. It does not
        run until you submit Search.
      </p>
      <div className="toolbar">
        <div className="field">
          <label htmlFor="member-kind">Kind</label>
          <select
            id="member-kind"
            value={kind}
            onChange={(event) => setKind(event.target.value === "group" ? "group" : "user")}
          >
            <option value="user">User</option>
            <option value="group">Group</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="member-q">Search</label>
          <input
            id="member-q"
            value={q}
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => setQ(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                event.preventDefault();
                void runSearch();
              }
            }}
          />
        </div>
        <button type="button" className="button-primary" disabled={searching} onClick={() => void runSearch()}>
          {searching ? "Searching…" : "Search"}
        </button>
      </div>
      {status !== undefined ? <p role="status" className="muted">{status}</p> : null}
      {results.length > 0 ? (
        <ul className="member-results">
          {results.map((item) => (
            <li key={memberKey(item)}>
              <span>
                {item.kind} <code>{item.id}</code>
              </span>
              <button
                type="button"
                onClick={() => onChange(uniqueMembers([...selected, item]))}
                disabled={selected.some((cur) => memberKey(cur) === memberKey(item))}
              >
                Add
              </button>
            </li>
          ))}
        </ul>
      ) : null}
      <h3>Selected members</h3>
      {selected.length === 0 ? (
        <p className="muted">None selected.</p>
      ) : (
        <ul className="member-selected">
          {selected.map((item) => (
            <li key={memberKey(item)}>
              <span>
                {item.kind} <code>{item.id}</code>
              </span>
              <button
                type="button"
                onClick={() => onChange(selected.filter((cur) => memberKey(cur) !== memberKey(item)))}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
      <FormError id="member-error" message={error} />
      <input
        type="hidden"
        id="members"
        name="members"
        value={selected.map((item) => memberKey(item)).join(",")}
        aria-invalid={error !== undefined}
        aria-describedby={describedBy([error !== undefined ? "member-error" : undefined])}
      />
    </fieldset>
  );
}

export function toMemberRefs(members: readonly MemberChoice[]): MemberRef[] {
  return uniqueMembers(members).map((member) => ({ kind: member.kind, id: member.id }));
}

async function searchMembers(kind: MemberKind, raw: string): Promise<MemberChoice[]> {
  const q = raw.trim();
  const query = q === "" ? { pageSize: MEMBER_SEARCH_PAGE_SIZE } : { pageSize: MEMBER_SEARCH_PAGE_SIZE, q };
  if (kind === "user") {
    const page = await listUsers(query);
    return page.items.map((user) => ({ kind: "user" as const, id: user.id }));
  }
  const page = await listGroups(query);
  return page.items.map((group) => ({ kind: "group" as const, id: group.id }));
}
