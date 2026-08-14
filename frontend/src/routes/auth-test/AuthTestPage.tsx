import { useState } from "react";
import { isApiError } from "../../api/problem";
import { createAuthTest } from "../../api/search";
import { useSession } from "../../auth/SessionGate";
import { useForm, z, zodResolver } from "../../lib/form";
import {
  BIND_TRANSPORTS,
  bindOutcomePresentation,
  bindRateLimitMessage,
  canSubmitBindTest,
  clearedBindPassword,
  type BindTransport,
} from "../../lib/ops-model";
import { hasScope, SCOPE_DIRECTORY_PASSWORD } from "../../lib/session-model";
import { describedBy, FormError, ResourcePage, ScopeNote } from "../shared/ResourcePage";

const bindSchema = z.object({
  identity: z.string().trim().min(1, "Enter a user ID or bind DN."),
  password: z.string().min(1, "Enter a password."),
  transport: z.enum(BIND_TRANSPORTS),
});

type BindValues = z.infer<typeof bindSchema>;

export function AuthTestPage() {
  const { session, canLogout } = useSession();
  const gate = canSubmitBindTest({
    hasPassword: hasScope(session.scopes, SCOPE_DIRECTORY_PASSWORD),
    csrfPresent: canLogout,
  });
  const [result, setResult] = useState<{ title: string; detail: string } | undefined>();
  const [notice, setNotice] = useState<string | undefined>();
  const form = useForm<BindValues>({
    resolver: zodResolver(bindSchema),
    defaultValues: { identity: "", password: "", transport: "ldaps" },
  });
  const identityError = form.formState.errors.identity?.message;
  const passwordError = form.formState.errors.password?.message;

  return (
    <ResourcePage title="Bind test">
      <ScopeNote scopes={session.scopes} required={SCOPE_DIRECTORY_PASSWORD} />
      {!gate.ok ? <p>{gate.reason}</p> : null}
      <p>
        Invalid credentials are an authorized diagnostic. The result does not
        reveal whether the identity is unknown.
      </p>
      <form
        method="post"
        noValidate
        onSubmit={form.handleSubmit(async (values) => {
          if (!gate.ok) {
            return;
          }
          const password = values.password;
          const transport: BindTransport = values.transport;
          form.setValue("password", "");
          setResult(undefined);
          setNotice(undefined);
          try {
            const body =
              transport === "ldaps"
                ? { identity: values.identity, password }
                : { identity: values.identity, password, transport };
            const out = await createAuthTest(body);
            setResult(bindOutcomePresentation(out.outcome));
          } catch (err) {
            form.reset({ ...form.getValues(), ...clearedBindPassword() });
            if (isApiError(err) && err.rateLimited) {
              setNotice(bindRateLimitMessage());
              return;
            }
            setNotice(isApiError(err) ? err.message : "Bind test failed.");
          }
        })}
      >
        <div className="field">
          <label htmlFor="bind-identity">Identity</label>
          <input
            id="bind-identity"
            autoComplete="username"
            spellCheck={false}
            aria-required="true"
            aria-invalid={identityError !== undefined}
            aria-describedby={describedBy([identityError !== undefined ? "bind-identity-error" : undefined])}
            {...form.register("identity")}
          />
          <FormError id="bind-identity-error" message={identityError} />
        </div>
        <div className="field">
          <label htmlFor="bind-password">Password</label>
          <input
            id="bind-password"
            type="password"
            autoComplete="off"
            aria-required="true"
            aria-invalid={passwordError !== undefined}
            aria-describedby={describedBy(["bind-password-hint", passwordError !== undefined ? "bind-password-error" : undefined])}
            {...form.register("password")}
          />
          <p id="bind-password-hint" className="field-hint">
            The password is cleared after the request and is never stored.
          </p>
          <FormError id="bind-password-error" message={passwordError} />
        </div>
        <div className="field">
          <label htmlFor="bind-transport">Transport</label>
          <select id="bind-transport" {...form.register("transport")}>
            {BIND_TRANSPORTS.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
        </div>
        <div className="form-actions">
          <button type="submit" disabled={!gate.ok || form.formState.isSubmitting}>
            {form.formState.isSubmitting ? "Testing…" : "Test bind"}
          </button>
        </div>
      </form>
      {notice !== undefined ? (
        <p role="alert">{notice}</p>
      ) : null}
      {result !== undefined ? (
        <section aria-labelledby="bind-result-heading">
          <h2 id="bind-result-heading">{result.title}</h2>
          <p role="status">{result.detail}</p>
        </section>
      ) : null}
    </ResourcePage>
  );
}
