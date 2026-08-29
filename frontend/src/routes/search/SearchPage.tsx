import { useState } from "react";
import { isApiError } from "../../api/problem";
import { searchEntries } from "../../api/search";
import type { SearchEntry, SearchPage } from "../../api/types";
import { useSession } from "../../auth/SessionGate";
import {
  DEFAULT_SEARCH_PAGE_SIZE,
  emptySearchForm,
  entryToLDIF,
  redactedAttrNames,
  requestedSearchAttributes,
  SEARCH_ALLOWED_ATTRS,
  SEARCH_SCOPES,
  searchBody,
  searchProblemMessage,
  toggleAttr,
  validSearchScope,
  type SearchFormValues,
} from "../../lib/search-model";
import { hasScope, SCOPE_DIRECTORY_READ } from "../../lib/session-model";
import { mapProblem } from "../../lib/a11y";
import { describedBy, FormError, ResourcePage, ScopeNote } from "../shared/ResourcePage";
import { LiveRegion, SafeText } from "../shared/SafeText";

export function SearchPage() {
  const { session } = useSession();
  const canRead = hasScope(session.scopes, SCOPE_DIRECTORY_READ);
  const [draft, setDraft] = useState<SearchFormValues>(emptySearchForm);
  const [submitted, setSubmitted] = useState<SearchFormValues | undefined>();
  const [cursor, setCursor] = useState("");
  const [prev, setPrev] = useState<string[]>([]);
  const [page, setPage] = useState<SearchPage | undefined>();
  const [busy, setBusy] = useState(false);
  const [errors, setErrors] = useState<Partial<Record<"base" | "filter" | "pageSize" | "cursor" | "attributes" | "form", string>>>({});
  const [copied, setCopied] = useState<string | undefined>();

  const runSearch = async (values: SearchFormValues, nextCursor: string, history: string[]): Promise<void> => {
    const blocked = requestedSearchAttributes(values.attributes).blocked;
    if (blocked.length > 0) {
      setErrors({ attributes: `${blocked.join(", ")} cannot be requested.` });
      return;
    }
    if (values.filter.trim() === "") {
      setErrors({ filter: searchProblemMessage([{ path: "filter", code: "empty", message: "empty" }], "").message });
      return;
    }
    setBusy(true);
    setErrors({});
    setCopied(undefined);
    try {
      const result = await searchEntries(searchBody(values, nextCursor));
      setSubmitted(values);
      setCursor(nextCursor);
      setPrev(history);
      setPage(result);
    } catch (err) {
      const fallback = isApiError(err)
        ? mapProblem({
            status: err.status,
            message: err.message,
            directoryUnavailable: err.directoryUnavailable,
            forbidden: err.forbidden,
            requiredScope: () => err.requiredScope(),
          }).message
        : "Search failed.";
      const mapped = isApiError(err)
        ? searchProblemMessage(err.fieldErrors(), fallback)
        : { field: "form" as const, message: fallback };
      setErrors({ [mapped.field]: mapped.message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <ResourcePage title="Search">
      <ScopeNote scopes={session.scopes} required={SCOPE_DIRECTORY_READ} />
      <p>
        Search does not run while you type. Submit the form to query the managed
        suffix.
      </p>
      {!canRead ? null : (
        <>
          <form
            className="search-form"
            method="post"
            noValidate
            onSubmit={(event) => {
              event.preventDefault();
              void runSearch(draft, "", []);
            }}
          >
            <div className="field">
              <label htmlFor="search-base">Base DN</label>
              <input
                id="search-base"
                value={draft.base}
                autoComplete="off"
                spellCheck={false}
                aria-invalid={errors.base !== undefined}
                aria-describedby={describedBy(["search-base-hint", errors.base !== undefined ? "search-base-error" : undefined])}
                onChange={(event) => setDraft({ ...draft, base: event.target.value })}
              />
              <p id="search-base-hint" className="field-hint">
                Empty uses the compiled managed suffix.
              </p>
              <FormError id="search-base-error" message={errors.base} />
            </div>
            <div className="field">
              <label htmlFor="search-scope">Scope</label>
              <select
                id="search-scope"
                value={draft.scope}
                onChange={(event) => setDraft({ ...draft, scope: validSearchScope(event.target.value) })}
              >
                {SEARCH_SCOPES.map((scope) => (
                  <option key={scope} value={scope}>
                    {scope}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor="search-filter">Filter</label>
              <input
                id="search-filter"
                value={draft.filter}
                autoComplete="off"
                spellCheck={false}
                aria-required="true"
                aria-invalid={errors.filter !== undefined}
                aria-describedby={describedBy(["search-filter-hint", errors.filter !== undefined ? "search-filter-error" : undefined])}
                onChange={(event) => setDraft({ ...draft, filter: event.target.value })}
              />
              <p id="search-filter-hint" className="field-hint">
                Example: (uid=alice). Match-all suffix searches are rejected.
              </p>
              <FormError id="search-filter-error" message={errors.filter} />
            </div>
            <div className="field">
              <label htmlFor="search-page-size">Page size</label>
              <input
                id="search-page-size"
                type="number"
                min={1}
                max={500}
                value={draft.pageSize}
                aria-invalid={errors.pageSize !== undefined}
                aria-describedby={describedBy([errors.pageSize !== undefined ? "search-page-size-error" : undefined])}
                onChange={(event) =>
                  setDraft({ ...draft, pageSize: Number.parseInt(event.target.value, 10) || DEFAULT_SEARCH_PAGE_SIZE })
                }
              />
              <FormError id="search-page-size-error" message={errors.pageSize} />
            </div>
            <fieldset aria-describedby={describedBy(["search-attr-hint", errors.attributes !== undefined ? "search-attr-error" : undefined])}>
              <legend>Attributes</legend>
              <p id="search-attr-hint" className="field-hint">
                Only allowlisted attributes can be requested. userPassword, aci,
                and operational attributes are blocked.
              </p>
              <div className="attr-choices">
                {SEARCH_ALLOWED_ATTRS.map((name) => (
                  <label key={name} className="choice">
                    <input
                      type="checkbox"
                      checked={draft.attributes.some((item) => item.toLowerCase() === name.toLowerCase())}
                      onChange={() => setDraft({ ...draft, attributes: toggleAttr(draft.attributes, name) })}
                    />{" "}
                    {name}
                  </label>
                ))}
              </div>
              <FormError id="search-attr-error" message={errors.attributes} />
            </fieldset>
            <div className="form-actions">
              <button type="submit" className="button-primary" disabled={busy}>
                {busy ? "Searching…" : "Search"}
              </button>
            </div>
            <LiveRegion message={errors.form} assertive />
            {errors.cursor !== undefined ? (
              <FormError id="search-cursor-error" message={errors.cursor} />
            ) : null}
          </form>
          {page !== undefined && submitted !== undefined ? (
            <SearchResults
              page={page}
              requested={requestedSearchAttributes(submitted.attributes).sent}
              copied={copied}
              onCopy={async (entry) => {
                const text = entryToLDIF(entry);
                try {
                  await navigator.clipboard.writeText(text);
                  setCopied(entry.dn);
                } catch {
                  setCopied(undefined);
                  setErrors({ form: "Could not copy the LDIF snippet." });
                }
              }}
              onPrev={() => {
                const history = [...prev];
                const back = history.pop() ?? "";
                void runSearch(submitted, back, history);
              }}
              onNext={() => {
                const next = page.nextCursor;
                if (next === undefined || next === "") {
                  return;
                }
                void runSearch(submitted, next, [...prev, cursor]);
              }}
              canPrev={prev.length > 0}
              busy={busy}
            />
          ) : null}
        </>
      )}
    </ResourcePage>
  );
}

function SearchResults({
  page,
  requested,
  copied,
  onCopy,
  onPrev,
  onNext,
  canPrev,
  busy,
}: {
  page: SearchPage;
  requested: readonly string[];
  copied: string | undefined;
  onCopy: (entry: SearchEntry) => void;
  onPrev: () => void;
  onNext: () => void;
  canPrev: boolean;
  busy: boolean;
}) {
  const missing = requested.length === 0 ? [] : redactedAttrNames(requested, flattenAttrs(page.entries));
  return (
    <section aria-labelledby="search-results-heading">
      <h2 id="search-results-heading">Results</h2>
      <p role="status">
        {page.entries.length} {page.entries.length === 1 ? "entry" : "entries"} on this page.
        Secret and operational attributes are omitted.
      </p>
      {missing.length > 0 ? (
        <p>Not returned (redacted or absent): {missing.join(", ")}.</p>
      ) : null}
      {page.entries.length === 0 ? (
        <p className="muted">No entries matched this search.</p>
      ) : (
        <table>
          <caption>Expand a row for attributes and a redacted LDIF snippet.</caption>
          <thead>
            <tr>
              <th scope="col">Entry</th>
            </tr>
          </thead>
          <tbody>
            {page.entries.map((entry) => (
              <tr key={entry.dn}>
                <td>
                  <details>
                    <summary><SafeText value={entry.dn} /></summary>
                    <AttrTable attributes={entry.attributes} />
                    <button type="button" onClick={() => onCopy(entry)}>
                      Copy LDIF
                    </button>
                    {copied === entry.dn ? (
                      <p role="status">Copied a redacted LDIF snippet.</p>
                    ) : null}
                  </details>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="pager">
        <button type="button" disabled={!canPrev || busy} onClick={onPrev}>
          Previous
        </button>
        <button type="button" disabled={page.nextCursor === undefined || page.nextCursor === "" || busy} onClick={onNext}>
          Next
        </button>
      </div>
    </section>
  );
}

function AttrTable({ attributes }: { attributes: SearchEntry["attributes"] }) {
  if (attributes.length === 0) {
    return <p className="muted">No allowlisted attributes were returned for this entry.</p>;
  }
  return (
    <table>
      <thead>
        <tr>
          <th scope="col">Name</th>
          <th scope="col">Value</th>
        </tr>
      </thead>
      <tbody>
        {attributes.map((attr, index) => (
          <tr key={`${attr.name}:${String(index)}`}>
            <th scope="row"><SafeText value={attr.name} /></th>
            <td><SafeText value={attr.value} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function flattenAttrs(entries: readonly SearchEntry[]): { name: string; value: string }[] {
  const out: { name: string; value: string }[] = [];
  for (const entry of entries) {
    out.push(...entry.attributes);
  }
  return out;
}
