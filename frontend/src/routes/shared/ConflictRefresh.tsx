import { useEffect, useRef } from "react";

export function ConflictRefresh({
  open,
  onRefresh,
  onDismiss,
}: {
  open: boolean;
  onRefresh: () => void;
  onDismiss: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const node = dialog.current;
    if (node === null) {
      return;
    }
    if (open && !node.open) {
      node.showModal();
    } else if (!open && node.open) {
      node.close();
    }
  }, [open]);

  return (
    <dialog ref={dialog} className="confirm-dialog" aria-labelledby="conflict-title" onClose={onDismiss}>
      <h2 id="conflict-title">Revision conflict</h2>
      <p>
        This record changed since you loaded it. Refresh to see the current
        revision. Your pending change was not applied.
      </p>
      <div className="form-actions">
        <button type="button" onClick={onRefresh}>
          Refresh
        </button>
        <button type="button" onClick={onDismiss}>
          Cancel
        </button>
      </div>
    </dialog>
  );
}
