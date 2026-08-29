import { useEffect, useRef, useState } from "react";
import { firstFocusable } from "../../lib/a11y";
import { exactIdConfirmed } from "../../lib/directory-model";
import { describedBy, FormError } from "./ResourcePage";

export function ConfirmDelete({
  open,
  resourceLabel,
  resourceId,
  disabled,
  onConfirm,
  onDismiss,
}: {
  open: boolean;
  resourceLabel: string;
  resourceId: string;
  disabled: boolean;
  onConfirm: () => void;
  onDismiss: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [typed, setTyped] = useState("");
  const matches = exactIdConfirmed(resourceId, typed);

  useEffect(() => {
    const node = dialog.current;
    if (node === null) {
      return;
    }
    if (open && !node.open) {
      setTyped("");
      node.showModal();
      firstFocusable(node);
    } else if (!open && node.open) {
      node.close();
    }
  }, [open]);

  return (
    <dialog ref={dialog} className="confirm-dialog" aria-labelledby="delete-title" onClose={onDismiss}>
      <h2 id="delete-title">Delete {resourceLabel}</h2>
      <p>
        This cannot be undone from the UI. Type the exact {resourceLabel} ID{" "}
        <code>{resourceId}</code> to confirm.
      </p>
      <form
        method="dialog"
        onSubmit={(event) => {
          event.preventDefault();
          if (!matches || disabled) {
            return;
          }
          onConfirm();
        }}
      >
        <div className="field">
          <label htmlFor="delete-confirm-id">{resourceLabel} ID</label>
          <input
            id="delete-confirm-id"
            value={typed}
            autoComplete="off"
            spellCheck={false}
            aria-required="true"
            aria-invalid={!matches && typed !== ""}
            aria-describedby={describedBy([!matches && typed !== "" ? "delete-confirm-error" : undefined])}
            onChange={(event) => setTyped(event.target.value)}
          />
          {!matches && typed !== "" ? (
            <FormError id="delete-confirm-error" message={`Type ${resourceId} exactly.`} />
          ) : null}
        </div>
        <div className="form-actions">
          <button type="submit" className="button-danger" disabled={!matches || disabled}>
            Delete
          </button>
          <button type="button" onClick={onDismiss}>
            Cancel
          </button>
        </div>
      </form>
    </dialog>
  );
}
