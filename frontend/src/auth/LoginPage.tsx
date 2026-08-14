import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router";
import { createSession, getSession, loginFailureKind, clearedLoginValues } from "../api/session";
import { zodResolver, useForm, z } from "../lib/form";
import { queryKeys } from "../lib/query";
import { loginNotice, type LoginNoticeKind } from "../lib/session-model";

const loginSchema = z.object({
  token: z.string().trim().min(1, "Enter a management token."),
});

type LoginValues = z.infer<typeof loginSchema>;

type LoginLocationState = {
  reason?: LoginNoticeKind;
};

export function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const queryClient = useQueryClient();
  const locationState = location.state as LoginLocationState | null;
  const [noticeKind, setNoticeKind] = useState<LoginNoticeKind | undefined>(
    locationState?.reason === "expired" ? "expired" : undefined,
  );
  const existing = useQuery({
    queryKey: queryKeys.session,
    queryFn: getSession,
    retry: false,
  });

  const form = useForm<LoginValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { token: "" },
  });

  if (existing.isPending) {
    return (
      <main className="login">
        <h1>LabLDAP sign in</h1>
        {noticeKind === "expired" ? (
          <p role="status" aria-live="assertive">
            {loginNotice("expired").message}
          </p>
        ) : null}
        <p role="status">Checking session…</p>
      </main>
    );
  }

  if (existing.data !== undefined) {
    return <Navigate to="/" replace />;
  }

  const notice = noticeKind === undefined ? undefined : loginNotice(noticeKind);
  const fieldError = form.formState.errors.token?.message;
  const describedBy = [notice ? "login-notice" : undefined, fieldError ? "login-token-error" : undefined]
    .filter((id): id is string => id !== undefined)
    .join(" ");

  return (
    <main className="login">
      <h1>LabLDAP sign in</h1>
      <p>Exchange a static management token for a browser session. The token is never stored.</p>
      {notice ? (
        <p id="login-notice" role={notice.role} aria-live="assertive">
          {notice.message}
        </p>
      ) : null}
      <form
        method="post"
        noValidate
        onSubmit={form.handleSubmit(async (values) => {
          const token = values.token;
          form.reset(clearedLoginValues());
          try {
            await createSession(token);
            const session = await getSession();
            queryClient.setQueryData(queryKeys.session, session);
            await navigate("/", { replace: true });
          } catch (err) {
            setNoticeKind(loginFailureKind(err));
          }
        })}
      >
        <div className="field">
          <label htmlFor="login-token">Management token</label>
          <input
            id="login-token"
            type="password"
            autoComplete="off"
            spellCheck={false}
            aria-required="true"
            aria-invalid={fieldError !== undefined || noticeKind === "invalid"}
            aria-describedby={describedBy === "" ? undefined : describedBy}
            {...form.register("token")}
          />
          {fieldError ? (
            <p id="login-token-error" className="field-error" role="alert">
              {fieldError}
            </p>
          ) : null}
        </div>
        <button type="submit" disabled={form.formState.isSubmitting}>
          {form.formState.isSubmitting ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </main>
  );
}
