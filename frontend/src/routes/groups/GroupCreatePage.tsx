import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate } from "react-router";
import { createGroup } from "../../api/groups";
import { isApiError } from "../../api/problem";
import { useSession } from "../../auth/SessionGate";
import {
  canSubmitGroupCreate,
  canSubmitMutation,
  emptyGroupExplanation,
  formFieldFromProblemPath,
  type MemberChoice,
} from "../../lib/directory-model";
import { useForm, z, zodResolver } from "../../lib/form";
import { invalidateUsersAndGroups } from "../../lib/query";
import { hasScope, SCOPE_DIRECTORY_WRITE } from "../../lib/session-model";
import { MemberSearch, toMemberRefs } from "../shared/MemberSearch";
import { describedBy, FormError, ResourcePage } from "../shared/ResourcePage";

const createSchema = z.object({
  id: z.string().trim().min(1, "Enter a group ID."),
});

type CreateValues = z.infer<typeof createSchema>;

export function GroupCreatePage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { session, canLogout } = useSession();
  const writeGate = canSubmitMutation({
    hasWrite: hasScope(session.scopes, SCOPE_DIRECTORY_WRITE),
    csrfPresent: canLogout,
  });
  const [members, setMembers] = useState<MemberChoice[]>([]);
  const [memberError, setMemberError] = useState<string | undefined>();
  const form = useForm<CreateValues>({
    resolver: zodResolver(createSchema),
    defaultValues: { id: "" },
  });
  const idError = form.formState.errors.id?.message;
  const memberGate = canSubmitGroupCreate(members);

  return (
    <ResourcePage title="Create group">
      <p>
        <Link to="/groups">Back to groups</Link>
      </p>
      <p>{emptyGroupExplanation()}</p>
      {!writeGate.ok ? <p>{writeGate.reason}</p> : null}
      <form
        method="post"
        noValidate
        onSubmit={form.handleSubmit(async (values) => {
          setMemberError(undefined);
          if (!writeGate.ok) {
            return;
          }
          if (!memberGate.ok) {
            setMemberError(memberGate.reason);
            return;
          }
          try {
            const created = await createGroup({ id: values.id, members: toMemberRefs(members) });
            await invalidateUsersAndGroups(queryClient);
            await navigate(`/groups/${encodeURIComponent(created.id)}`);
          } catch (err) {
            if (!isApiError(err)) {
              setMemberError("Group create failed.");
              return;
            }
            for (const field of err.fieldErrors()) {
              const name = formFieldFromProblemPath(field.path);
              if (name === "id") {
                form.setError("id", { type: "server", message: field.message });
              }
              if (name === "members") {
                setMemberError(field.message);
              }
            }
            if (err.fieldErrors().length === 0) {
              form.setError("id", { type: "server", message: err.message });
            }
          }
        })}
      >
        <div className="field">
          <label htmlFor="group-id">Group ID</label>
          <input
            id="group-id"
            autoComplete="off"
            spellCheck={false}
            aria-required="true"
            aria-invalid={idError !== undefined}
            aria-describedby={describedBy([idError !== undefined ? "group-id-error" : undefined])}
            {...form.register("id")}
          />
          <FormError id="group-id-error" message={idError} />
        </div>
        <MemberSearch
          legend="Initial member (required)"
          selected={members}
          onChange={setMembers}
          disabled={!writeGate.ok}
          error={memberError ?? (memberGate.ok ? undefined : memberGate.reason)}
        />
        <div className="form-actions">
          <button type="submit" disabled={!writeGate.ok || !memberGate.ok || form.formState.isSubmitting}>
            {form.formState.isSubmitting ? "Creating…" : "Create group"}
          </button>
        </div>
      </form>
    </ResourcePage>
  );
}
