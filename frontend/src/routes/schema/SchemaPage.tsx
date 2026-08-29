import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import type { KeyboardEvent } from "react";
import { getRootDSE, getSchema } from "../../api/schema";
import type { AttributeType, ObjectClass, RootDSE } from "../../api/types";
import { useSession } from "../../auth/SessionGate";
import { filterNamed, moveIndex, schemaSearchEmpty } from "../../lib/ops-model";
import { queryKeys } from "../../lib/query";
import { hasScope, SCOPE_SCHEMA_READ } from "../../lib/session-model";
import { QueryStatus, ResourcePage, ScopeNote } from "../shared/ResourcePage";

type SchemaKind = "objectClass" | "attribute";

export function SchemaPage() {
  const { session } = useSession();
  const canRead = hasScope(session.scopes, SCOPE_SCHEMA_READ);
  const rootQuery = useQuery({
    queryKey: queryKeys.directory.rootdse,
    queryFn: getRootDSE,
    enabled: canRead,
  });
  const schemaQuery = useQuery({
    queryKey: queryKeys.directory.schema,
    queryFn: getSchema,
    enabled: canRead,
  });
  const [ocQuery, setOcQuery] = useState("");
  const [atQuery, setAtQuery] = useState("");
  const [selected, setSelected] = useState<{ kind: SchemaKind; name: string } | undefined>();
  const [ocIndex, setOcIndex] = useState(0);
  const [atIndex, setAtIndex] = useState(0);

  const objectClasses = useMemo(
    () => filterNamed(schemaQuery.data?.objectClasses ?? [], ocQuery),
    [schemaQuery.data?.objectClasses, ocQuery],
  );
  const attributes = useMemo(
    () => filterNamed(schemaQuery.data?.attributes ?? [], atQuery),
    [schemaQuery.data?.attributes, atQuery],
  );
  const selectedObject = selected?.kind === "objectClass"
    ? objectClasses.find((item) => item.name === selected.name)
    : undefined;
  const selectedAttr = selected?.kind === "attribute"
    ? attributes.find((item) => item.name === selected.name)
    : undefined;

  return (
    <ResourcePage title="Schema">
      <ScopeNote scopes={session.scopes} required={SCOPE_SCHEMA_READ} error={schemaQuery.error ?? rootQuery.error} />
      <p>Schema is read-only. Use the lists to inspect object classes and attributes.</p>
      {!canRead ? null : (
        <>
          <section aria-labelledby="rootdse-heading">
            <h2 id="rootdse-heading">Root DSE</h2>
            {rootQuery.data === undefined ? (
              <QueryStatus result={rootQuery} missing="Root DSE" />
            ) : (
              <RootDSEView dse={rootQuery.data} />
            )}
          </section>
          {schemaQuery.data === undefined ? (
            <QueryStatus result={schemaQuery} missing="schema" />
          ) : (
            <div className="schema-browser">
              <SchemaList
                id="objectclass"
                title="Object classes"
                items={objectClasses}
                query={ocQuery}
                activeIndex={ocIndex}
                selectedName={selected?.kind === "objectClass" ? selected.name : undefined}
                empty={schemaSearchEmpty("object classes", ocQuery.trim() !== "")}
                onQuery={(value) => {
                  setOcQuery(value);
                  setOcIndex(0);
                }}
                onIndex={setOcIndex}
                onSelect={(name) => setSelected({ kind: "objectClass", name })}
              />
              <SchemaList
                id="attribute"
                title="Attributes"
                items={attributes}
                query={atQuery}
                activeIndex={atIndex}
                selectedName={selected?.kind === "attribute" ? selected.name : undefined}
                empty={schemaSearchEmpty("attributes", atQuery.trim() !== "")}
                onQuery={(value) => {
                  setAtQuery(value);
                  setAtIndex(0);
                }}
                onIndex={setAtIndex}
                onSelect={(name) => setSelected({ kind: "attribute", name })}
              />
            </div>
          )}
          <section aria-labelledby="schema-detail-heading">
            <h2 id="schema-detail-heading">Details</h2>
            {selectedObject !== undefined ? (
              <ObjectClassView oc={selectedObject} />
            ) : selectedAttr !== undefined ? (
              <AttributeView attr={selectedAttr} />
            ) : (
              <p className="muted">Select an object class or attribute from the lists.</p>
            )}
          </section>
        </>
      )}
    </ResourcePage>
  );
}

function RootDSEView({ dse }: { dse: RootDSE }) {
  return (
    <dl>
      <div>
        <dt>Vendor</dt>
        <dd>{display(dse.vendorName)} {display(dse.vendorVersion)}</dd>
      </div>
      <div>
        <dt>Naming contexts</dt>
        <dd>{joinList(dse.namingContexts)}</dd>
      </div>
      <div>
        <dt>Supported controls</dt>
        <dd>{joinList(dse.supportedControls)}</dd>
      </div>
      <div>
        <dt>SASL</dt>
        <dd>{joinList(dse.supportedSASL)}</dd>
      </div>
    </dl>
  );
}

function SchemaList<T extends { name: string }>({
  id,
  title,
  items,
  query,
  activeIndex,
  selectedName,
  empty,
  onQuery,
  onIndex,
  onSelect,
}: {
  id: string;
  title: string;
  items: readonly T[];
  query: string;
  activeIndex: number;
  selectedName: string | undefined;
  empty: string;
  onQuery: (value: string) => void;
  onIndex: (index: number) => void;
  onSelect: (name: string) => void;
}) {
  const listId = `${id}-list`;
  const inputId = `${id}-filter`;
  const active = items[activeIndex];

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement | HTMLUListElement>): void => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      const next = moveIndex(activeIndex, 1, items.length);
      onIndex(next);
      const item = items[next];
      if (item !== undefined) {
        onSelect(item.name);
      }
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      const next = moveIndex(activeIndex, -1, items.length);
      onIndex(next);
      const item = items[next];
      if (item !== undefined) {
        onSelect(item.name);
      }
    } else if (event.key === "Home") {
      event.preventDefault();
      onIndex(0);
      const item = items[0];
      if (item !== undefined) {
        onSelect(item.name);
      }
    } else if (event.key === "End") {
      event.preventDefault();
      const next = items.length - 1;
      onIndex(next);
      const item = items[next];
      if (item !== undefined) {
        onSelect(item.name);
      }
    } else if (event.key === "Enter" && active !== undefined) {
      event.preventDefault();
      onSelect(active.name);
    }
  };

  return (
    <section aria-labelledby={`${id}-heading`}>
      <h2 id={`${id}-heading`}>{title}</h2>
      <div className="field">
        <label htmlFor={inputId}>Filter {title.toLowerCase()}</label>
        <input
          id={inputId}
          value={query}
          autoComplete="off"
          spellCheck={false}
          role="combobox"
          aria-expanded="true"
          aria-controls={listId}
          aria-activedescendant={active === undefined ? undefined : `${id}-opt-${active.name}`}
          onChange={(event) => onQuery(event.target.value)}
          onKeyDown={onKeyDown}
        />
      </div>
      {items.length === 0 ? (
        <p className="muted">{empty}</p>
      ) : (
        <ul
          id={listId}
          role="listbox"
          tabIndex={0}
          aria-label={title}
          onKeyDown={onKeyDown}
        >
          {items.map((item, index) => (
            <li
              key={item.name}
              id={`${id}-opt-${item.name}`}
              role="option"
              aria-selected={selectedName === item.name || activeIndex === index}
              className={activeIndex === index ? "is-active" : undefined}
              onClick={() => {
                onIndex(index);
                onSelect(item.name);
              }}
            >
              {item.name}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function ObjectClassView({ oc }: { oc: ObjectClass }) {
  return (
    <dl>
      <div>
        <dt>Name</dt>
        <dd>{oc.name}</dd>
      </div>
      <div>
        <dt>OID</dt>
        <dd>{display(oc.oid)}</dd>
      </div>
      <div>
        <dt>Kind</dt>
        <dd>{display(oc.kind)}</dd>
      </div>
      <div>
        <dt>Must</dt>
        <dd>{joinList(oc.must)}</dd>
      </div>
      <div>
        <dt>May</dt>
        <dd>{joinList(oc.may)}</dd>
      </div>
      <div>
        <dt>Superior</dt>
        <dd>{joinList(oc.sup)}</dd>
      </div>
    </dl>
  );
}

function AttributeView({ attr }: { attr: AttributeType }) {
  return (
    <dl>
      <div>
        <dt>Name</dt>
        <dd>{attr.name}</dd>
      </div>
      <div>
        <dt>OID</dt>
        <dd>{display(attr.oid)}</dd>
      </div>
      <div>
        <dt>Syntax</dt>
        <dd>{display(attr.syntax)}</dd>
      </div>
      <div>
        <dt>Single value</dt>
        <dd>{attr.singleValue === true ? "Yes" : "No"}</dd>
      </div>
    </dl>
  );
}

function display(value: string | undefined): string {
  return value === undefined || value === "" ? "—" : value;
}

function joinList(values: readonly string[] | undefined): string {
  if (values === undefined || values.length === 0) {
    return "—";
  }
  return values.join(", ");
}
