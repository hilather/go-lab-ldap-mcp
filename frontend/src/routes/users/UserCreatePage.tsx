import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router";
import { getCapabilities } from "../../api/directory";
import { isApiError } from "../../api/problem";
import { createUser } from "../../api/users";
import { useSession } from "../../auth/SessionGate";
import {
  ALLOWED_USER_ATTRS,
  canSubmitMutation,
  firstForbiddenAttr,
  mappedFormErrors,
  passwordPolicyHints,
  passwordsMatch,
  reservedCreateIdMessage,
  toUserSpecBody,
  type AttrRow,
} from "../../lib/directory-model";
import { useForm, z, zodResolver } from "../../lib/form";
import { invalidateUsersAndGroups, queryKeys } from "../../lib/query";
import { hasScope, SCOPE_DIRECTORY_WRITE } from "../../lib/session-model";
import { describedBy, FormError, ResourcePage } from "../shared/ResourcePage";

const createSchema = z
  .object({
    id: z
      .string()
      .trim()
      .min(1, "Enter a user ID.")
      .refine((value) => reservedCreateIdMessage(value) === undefined, {
        message: reservedCreateIdMessage("new") ?? 'The ID "new" is reserved.',
      }),
    uid: z.string(),
    enabled: z.boolean(),
    password: z.string().min(1, "Enter a password."),
    confirmPassword: z.string(),
    attributes: z.array(z.object({ name: z.string(), value: z.string() })),
  })
  .superRefine((values, ctx) => {
    if (!passwordsMatch(values.password, values.confirmPassword)) {
      ctx.addIssue({ code: "custom", path: ["confirmPassword"], message: "Passwords do not match." });
    }
    const forbidden = firstForbiddenAttr(values.attributes);
    if (forbidden !== undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["attributes"],
        message: `${forbidden} is not an allowlisted user attribute.`,
      });
    }
  });

type CreateValues = z.infer<typeof createSchema>;

export function UserCreatePage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { session, canLogout } = useSession();
  const gate = canSubmitMutation({
    hasWrite: hasScope(session.scopes, SCOPE_DIRECTORY_WRITE),
    csrfPresent: canLogout,
  });
  const caps = useQuery({
    queryKey: queryKeys.directory.capabilities,
    queryFn: getCapabilities,
  });
  const form = useForm<CreateValues>({
    resolver: zodResolver(createSchema),
    defaultValues: {
      id: "",
      uid: "",
      enabled: true,
      password: "",
      confirmPassword: "",
      attributes: [],
    },
  });
  const hints = passwordPolicyHints(caps.data?.passwordScheme);
  const idError = form.formState.errors.id?.message;
  const uidError = form.formState.errors.uid?.message;
  const passwordError = form.formState.errors.password?.message;
  const confirmError = form.formState.errors.confirmPassword?.message;
  const attrError = form.formState.errors.attributes?.message;
  const attributes = form.watch("attributes");

  return (
    <ResourcePage title="Create user">
      <p>
        <Link to="/users">Back to users</Link>
      </p>
      {!gate.ok ? <p>{gate.reason}</p> : null}
      <ul className="hint-list">
        {hints.map((hint) => (
          <li key={hint}>{hint}</li>
        ))}
      </ul>
      <form
        method="post"
        noValidate
        onSubmit={form.handleSubmit(async (values) => {
          if (!gate.ok) {
            return;
          }
          const spec = toUserSpecBody(values);
          form.setValue("password", "");
          form.setValue("confirmPassword", "");
          try {
            const created = await createUser(spec);
            await invalidateUsersAndGroups(queryClient);
            await navigate(`/users/${encodeURIComponent(created.id)}`);
          } catch (err) {
            applyCreateErrors(form.setError, err);
          }
        })}
      >
        <div className="field">
          <label htmlFor="user-id">User ID</label>
          <input
            id="user-id"
            autoComplete="off"
            spellCheck={false}
            aria-required="true"
            aria-invalid={idError !== undefined}
            aria-describedby={describedBy([idError !== undefined ? "user-id-error" : undefined])}
            {...form.register("id")}
          />
          <FormError id="user-id-error" message={idError} />
        </div>
        <div className="field">
          <label htmlFor="user-uid">UID (optional, defaults to ID)</label>
          <input
            id="user-uid"
            autoComplete="off"
            spellCheck={false}
            aria-invalid={uidError !== undefined}
            aria-describedby={describedBy([uidError !== undefined ? "user-uid-error" : undefined])}
            {...form.register("uid")}
          />
          <FormError id="user-uid-error" message={uidError} />
        </div>
        <div className="field">
          <label htmlFor="user-enabled">
            <input id="user-enabled" type="checkbox" {...form.register("enabled")} /> Enabled
          </label>
        </div>
        <div className="field">
          <label htmlFor="user-password">Password</label>
          <input
            id="user-password"
            type="password"
            autoComplete="new-password"
            aria-required="true"
            aria-invalid={passwordError !== undefined}
            aria-describedby={describedBy(["user-password-hint", passwordError !== undefined ? "user-password-error" : undefined])}
            {...form.register("password")}
          />
          <p id="user-password-hint" className="field-hint">
            Password fields are cleared after success or failure.
          </p>
          <FormError id="user-password-error" message={passwordError} />
        </div>
        <div className="field">
          <label htmlFor="user-confirm">Confirm password</label>
          <input
            id="user-confirm"
            type="password"
            autoComplete="new-password"
            aria-invalid={confirmError !== undefined}
            aria-describedby={describedBy([confirmError !== undefined ? "user-confirm-error" : undefined])}
            {...form.register("confirmPassword")}
          />
          <FormError id="user-confirm-error" message={confirmError} />
        </div>
        <fieldset aria-describedby={describedBy([attrError !== undefined ? "user-attr-error" : undefined])}>
          <legend>Advanced allowlisted attributes</legend>
          <p>Operational attributes, <code>userPassword</code>, and <code>memberOf</code> are rejected.</p>
          {attributes.map((row, index) => (
            <div className="attr-row" key={`${row.name}-${String(index)}`}>
              <label htmlFor={`attr-name-${String(index)}`}>Name</label>
              <select id={`attr-name-${String(index)}`} {...form.register(`attributes.${index}.name`)}>
                <option value="">Select</option>
                {ALLOWED_USER_ATTRS.map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </select>
              <label htmlFor={`attr-value-${String(index)}`}>Value</label>
              <input id={`attr-value-${String(index)}`} {...form.register(`attributes.${index}.value`)} />
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
          <button
            type="button"
            onClick={() => form.setValue("attributes", [...attributes, emptyAttrRow()])}
          >
            Add attribute
          </button>
          <FormError id="user-attr-error" message={attrError} />
        </fieldset>
        <div className="form-actions">
          <button type="submit" disabled={!gate.ok || form.formState.isSubmitting}>
            {form.formState.isSubmitting ? "Creating…" : "Create user"}
          </button>
        </div>
      </form>
    </ResourcePage>
  );
}

function emptyAttrRow(): AttrRow {
  return { name: "", value: "" };
}

function applyCreateErrors(
  setError: (name: "id" | "uid" | "password" | "attributes", error: { type: string; message: string }) => void,
  err: unknown,
): void {
  if (!isApiError(err)) {
    setError("id", { type: "server", message: "User create failed." });
    return;
  }
  const mapped = mappedFormErrors(err.fieldErrors(), ["id", "uid", "password", "attributes"]);
  if (mapped.length === 0) {
    setError("id", { type: "server", message: err.message });
    return;
  }
  for (const field of mapped) {
    if (field.name === "id" || field.name === "uid" || field.name === "password" || field.name === "attributes") {
      setError(field.name, { type: "server", message: field.message });
    }
  }
}
