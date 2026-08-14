import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { getCapabilities } from "../../api/directory";
import { isApiError } from "../../api/problem";
import type { User, UserPatch } from "../../api/types";
import {
  deleteUser,
  disableUser,
  enableUser,
  getUser,
  listUserGroups,
  setUserPassword,
  updateUser,
} from "../../api/users";
import { useSession } from "../../auth/SessionGate";
import {
  ALLOWED_USER_ATTRS,
  attributeMapFromRows,
  attributeRowsFromPairs,
  canSubmitMutation,
  canSubmitPassword,
  clearedPasswordFields,
  firstForbiddenAttr,
  formFieldFromProblemPath,
  passwordPolicyHints,
  passwordsMatch,
} from "../../lib/directory-model";
import { useForm, z, zodResolver } from "../../lib/form";
import { invalidateUsersAndGroups, queryKeys } from "../../lib/query";
import {
  hasScope,
  SCOPE_DIRECTORY_PASSWORD,
  SCOPE_DIRECTORY_READ,
  SCOPE_DIRECTORY_WRITE,
} from "../../lib/session-model";
import { ConfirmDelete } from "../shared/ConfirmDelete";
import { ConflictRefresh } from "../shared/ConflictRefresh";
import { describedBy, FormError, QueryStatus, ResourcePage, ScopeNote } from "../shared/ResourcePage";

const editSchema = z.object({
  enabled: z.boolean(),
  attributes: z.array(z.object({ name: z.string(), value: z.string() })),
});

const passwordSchema = z
  .object({
    password: z.string().min(1, "Enter a password."),
    confirmPassword: z.string(),
  })
  .superRefine((values, ctx) => {
    if (!passwordsMatch(values.password, values.confirmPassword)) {
      ctx.addIssue({ code: "custom", path: ["confirmPassword"], message: "Passwords do not match." });
    }
  });

type EditValues = z.infer<typeof editSchema>;
type PasswordValues = z.infer<typeof passwordSchema>;

export function UserDetailPage() {
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
  const passwordGate = canSubmitPassword({
    hasPassword: hasScope(session.scopes, SCOPE_DIRECTORY_PASSWORD),
    csrfPresent: canLogout,
  });
  const [conflict, setConflict] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [passwordOpen, setPasswordOpen] = useState(false);
  const [notice, setNotice] = useState<string | undefined>();

  const userQuery = useQuery({
    queryKey: queryKeys.users.detail(id),
    queryFn: () => getUser(id),
    enabled: canRead && id !== "",
  });
  const groupsQuery = useQuery({
    queryKey: queryKeys.users.groups(id),
    queryFn: () => listUserGroups(id),
    enabled: canRead && id !== "",
  });
  const caps = useQuery({
    queryKey: queryKeys.directory.capabilities,
    queryFn: getCapabilities,
    enabled: passwordOpen,
  });
  const user = userQuery.data;

  const refresh = async (): Promise<void> => {
    setConflict(false);
    await queryClient.invalidateQueries({ queryKey: queryKeys.users.detail(id) });
    await queryClient.invalidateQueries({ queryKey: queryKeys.users.groups(id) });
  };

  const runMutation = async (work: () => Promise<unknown>): Promise<void> => {
    setNotice(undefined);
    try {
      await work();
      await invalidateUsersAndGroups(queryClient);
      await refresh();
    } catch (err) {
      if (isApiError(err) && err.revisionConflict) {
        setConflict(true);
        return;
      }
      setNotice(isApiError(err) ? err.message : "The change was not applied.");
    }
  };

  return (
    <ResourcePage title={user === undefined ? "User" : `User ${user.id}`}>
      <p>
        <Link to="/users">Back to users</Link>
      </p>
      <ScopeNote scopes={session.scopes} required={SCOPE_DIRECTORY_READ} error={userQuery.error} />
      {user === undefined ? (
        <QueryStatus result={userQuery} missing="user" />
      ) : (
        <>
          {notice !== undefined ? (
            <p role="alert">{notice}</p>
          ) : null}
          <section aria-labelledby="user-overview-heading">
            <h2 id="user-overview-heading">Overview</h2>
            <dl>
              <div>
                <dt>ID</dt>
                <dd>
                  <code>{user.id}</code>
                </dd>
              </div>
              <div>
                <dt>UID</dt>
                <dd>
                  <code>{user.uid}</code>
                </dd>
              </div>
              <div>
                <dt>DN</dt>
                <dd>
                  <code>{user.dn}</code>
                </dd>
              </div>
              <div>
                <dt>Auth state</dt>
                <dd>{user.enabled ? "Enabled" : "Disabled"}</dd>
              </div>
              <div>
                <dt>Revision</dt>
                <dd>
                  <code>{user.revision}</code>
                </dd>
              </div>
              <div>
                <dt>Object classes</dt>
                <dd>{user.objectClasses.join(", ")}</dd>
              </div>
            </dl>
          </section>

          <section aria-labelledby="user-attrs-heading">
            <h2 id="user-attrs-heading">Attributes</h2>
            {user.attributes.length === 0 ? (
              <p>No allowlisted attributes are present.</p>
            ) : (
              <table>
                <caption>API-exposed attributes. Passwords and operational attributes are omitted.</caption>
                <thead>
                  <tr>
                    <th scope="col">Name</th>
                    <th scope="col">Value</th>
                  </tr>
                </thead>
                <tbody>
                  {user.attributes.map((attr) => (
                    <tr key={`${attr.name}:${attr.value}`}>
                      <th scope="row">{attr.name}</th>
                      <td>{attr.value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>

          <section aria-labelledby="user-groups-heading">
            <h2 id="user-groups-heading">Groups</h2>
            {groupsQuery.data === undefined ? (
              <QueryStatus result={groupsQuery} missing="user groups" />
            ) : groupsQuery.data.items.length === 0 ? (
              <p>This user is not a direct member of any group.</p>
            ) : (
              <ul>
                {groupsQuery.data.items.map((group) => (
                  <li key={group.id}>
                    <Link to={`/groups/${encodeURIComponent(group.id)}`}>{group.id}</Link>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <UserEditForm
            user={user}
            gate={writeGate}
            onSave={(patch) => runMutation(() => updateUser(user.id, patch, user.revision))}
          />

          <section aria-labelledby="user-actions-heading">
            <h2 id="user-actions-heading">Account actions</h2>
            {!writeGate.ok ? <p>{writeGate.reason}</p> : null}
            <div className="form-actions">
              <button
                type="button"
                disabled={!writeGate.ok || user.enabled}
                onClick={() => void runMutation(() => enableUser(user.id, user.revision))}
              >
                Enable
              </button>
              <button
                type="button"
                disabled={!writeGate.ok || !user.enabled}
                onClick={() => void runMutation(() => disableUser(user.id, user.revision))}
              >
                Disable
              </button>
              <button type="button" disabled={!passwordGate.ok} onClick={() => setPasswordOpen(true)}>
                Set password
              </button>
              <button type="button" disabled={!writeGate.ok} onClick={() => setDeleteOpen(true)}>
                Delete
              </button>
            </div>
            {!passwordGate.ok ? <p>{passwordGate.reason}</p> : null}
          </section>

          <PasswordDialog
            open={passwordOpen}
            hints={passwordPolicyHints(caps.data?.passwordScheme)}
            disabled={!passwordGate.ok}
            onDismiss={() => setPasswordOpen(false)}
            onSave={async (password) => {
              try {
                await setUserPassword(user.id, password, user.revision);
                setPasswordOpen(false);
                await invalidateUsersAndGroups(queryClient);
                await refresh();
              } catch (err) {
                if (isApiError(err) && err.revisionConflict) {
                  setPasswordOpen(false);
                  setConflict(true);
                  return;
                }
                throw err;
              }
            }}
          />

          <ConfirmDelete
            open={deleteOpen}
            resourceLabel="user"
            resourceId={user.id}
            disabled={!writeGate.ok}
            onDismiss={() => setDeleteOpen(false)}
            onConfirm={() => {
              void (async () => {
                try {
                  await deleteUser(user.id, user.revision);
                  await invalidateUsersAndGroups(queryClient);
                  await navigate("/users");
                } catch (err) {
                  setDeleteOpen(false);
                  if (isApiError(err) && err.revisionConflict) {
                    setConflict(true);
                    return;
                  }
                  setNotice(isApiError(err) ? err.message : "User delete failed.");
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

function UserEditForm({
  user,
  gate,
  onSave,
}: {
  user: User;
  gate: { ok: boolean; reason: string };
  onSave: (patch: UserPatch) => Promise<void>;
}) {
  const form = useForm<EditValues>({
    resolver: zodResolver(editSchema),
    defaultValues: {
      enabled: user.enabled,
      attributes: attributeRowsFromPairs(user.attributes),
    },
  });

  useEffect(() => {
    form.reset({
      enabled: user.enabled,
      attributes: attributeRowsFromPairs(user.attributes),
    });
  }, [form, user.enabled, user.revision, user.attributes]);

  const attributes = form.watch("attributes");
  const attrError = form.formState.errors.attributes?.message;

  return (
    <section aria-labelledby="user-edit-heading">
      <h2 id="user-edit-heading">Edit</h2>
      {!gate.ok ? <p>{gate.reason}</p> : null}
      <form
        method="post"
        noValidate
        onSubmit={form.handleSubmit(async (values) => {
          if (!gate.ok) {
            return;
          }
          const forbidden = firstForbiddenAttr(values.attributes);
          if (forbidden !== undefined) {
            form.setError("attributes", {
              type: "validate",
              message: `${forbidden} is not an allowlisted user attribute.`,
            });
            return;
          }
          const patch: UserPatch = { enabled: values.enabled };
          const attributesMap = attributeMapFromRows(values.attributes);
          if (attributesMap !== undefined) {
            patch.attributes = attributesMap;
          }
          try {
            await onSave(patch);
          } catch (err) {
            if (isApiError(err)) {
              for (const field of err.fieldErrors()) {
                const name = formFieldFromProblemPath(field.path);
                if (name === "attributes") {
                  form.setError("attributes", { type: "server", message: field.message });
                }
              }
            }
          }
        })}
      >
        <div className="field">
          <label htmlFor="edit-enabled">
            <input id="edit-enabled" type="checkbox" disabled={!gate.ok} {...form.register("enabled")} /> Enabled
          </label>
        </div>
        <fieldset disabled={!gate.ok} aria-describedby={describedBy([attrError !== undefined ? "edit-attr-error" : undefined])}>
          <legend>Allowlisted attributes</legend>
          {attributes.map((row, index) => (
            <div className="attr-row" key={`${row.name}-${String(index)}`}>
              <label htmlFor={`edit-attr-name-${String(index)}`}>Name</label>
              <select id={`edit-attr-name-${String(index)}`} {...form.register(`attributes.${index}.name`)}>
                <option value="">Select</option>
                {ALLOWED_USER_ATTRS.map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </select>
              <label htmlFor={`edit-attr-value-${String(index)}`}>Value</label>
              <input id={`edit-attr-value-${String(index)}`} {...form.register(`attributes.${index}.value`)} />
              <button
                type="button"
                onClick={() =>
                  form.setValue(
                    "attributes",
                    attributes.filter((_, i) => i !== index),
                  )
                }
              >
                Remove
              </button>
            </div>
          ))}
          <button type="button" onClick={() => form.setValue("attributes", [...attributes, { name: "", value: "" }])}>
            Add attribute
          </button>
          <FormError id="edit-attr-error" message={attrError} />
        </fieldset>
        <div className="form-actions">
          <button type="submit" disabled={!gate.ok || form.formState.isSubmitting}>
            {form.formState.isSubmitting ? "Saving…" : "Save changes"}
          </button>
        </div>
      </form>
    </section>
  );
}

function PasswordDialog({
  open,
  hints,
  disabled,
  onSave,
  onDismiss,
}: {
  open: boolean;
  hints: string[];
  disabled: boolean;
  onSave: (password: string) => Promise<void>;
  onDismiss: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const form = useForm<PasswordValues>({
    resolver: zodResolver(passwordSchema),
    defaultValues: clearedPasswordFields(),
  });
  const passwordError = form.formState.errors.password?.message;
  const confirmError = form.formState.errors.confirmPassword?.message;
  const [formError, setFormError] = useState<string | undefined>();

  useEffect(() => {
    const node = dialog.current;
    if (node === null) {
      return;
    }
    if (open && !node.open) {
      form.reset(clearedPasswordFields());
      setFormError(undefined);
      node.showModal();
    } else if (!open && node.open) {
      node.close();
    }
  }, [form, open]);

  return (
    <dialog ref={dialog} className="confirm-dialog" aria-labelledby="password-title" onClose={onDismiss}>
      <h2 id="password-title">Set password</h2>
      <ul className="hint-list">
        {hints.map((hint) => (
          <li key={hint}>{hint}</li>
        ))}
      </ul>
      <form
        method="dialog"
        noValidate
        onSubmit={form.handleSubmit(async (values) => {
          const password = values.password;
          form.reset(clearedPasswordFields());
          setFormError(undefined);
          try {
            await onSave(password);
          } catch (err) {
            if (isApiError(err) && err.rateLimited) {
              setFormError("Too many password changes. Wait a minute and try again.");
              return;
            }
            setFormError(isApiError(err) ? err.message : "Password update failed.");
          }
        })}
      >
        <div className="field">
          <label htmlFor="set-password">New password</label>
          <input
            id="set-password"
            type="password"
            autoComplete="new-password"
            aria-required="true"
            aria-invalid={passwordError !== undefined}
            aria-describedby={describedBy([passwordError !== undefined ? "set-password-error" : undefined])}
            {...form.register("password")}
          />
          <FormError id="set-password-error" message={passwordError} />
        </div>
        <div className="field">
          <label htmlFor="set-confirm">Confirm password</label>
          <input
            id="set-confirm"
            type="password"
            autoComplete="new-password"
            aria-invalid={confirmError !== undefined}
            aria-describedby={describedBy([confirmError !== undefined ? "set-confirm-error" : undefined])}
            {...form.register("confirmPassword")}
          />
          <FormError id="set-confirm-error" message={confirmError} />
        </div>
        <FormError id="set-password-form-error" message={formError} />
        <div className="form-actions">
          <button type="submit" disabled={disabled || form.formState.isSubmitting}>
            {form.formState.isSubmitting ? "Saving…" : "Update password"}
          </button>
          <button type="button" onClick={onDismiss}>
            Cancel
          </button>
        </div>
      </form>
    </dialog>
  );
}
