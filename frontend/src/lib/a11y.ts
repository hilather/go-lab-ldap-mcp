// Shared error and accessibility helpers. No React so node:test can load this
// file with type stripping.

export type ProblemLike = {
  status: number;
  message: string;
  revisionConflict?: boolean;
  directoryUnavailable?: boolean;
  forbidden?: boolean;
  requiredScope?: () => string | undefined;
};

export type Announcement = {
  role: "alert" | "status";
  message: string;
};

export function mapProblem(err: ProblemLike): Announcement {
  if (err.revisionConflict === true) {
    return { role: "alert", message: "This record changed. Refresh and try again." };
  }
  if (err.directoryUnavailable === true) {
    return {
      role: "alert",
      message: "Directory outage: the control plane cannot complete this operation.",
    };
  }
  if (err.forbidden === true) {
    const scope = err.requiredScope?.();
    return {
      role: "alert",
      message: scope !== undefined && scope !== "" ? `Requires scope ${scope}.` : "This action is not permitted.",
    };
  }
  if (err.status === 429) {
    return { role: "alert", message: "Too many requests. Wait and try again." };
  }
  const message = err.message.trim();
  return { role: "alert", message: message === "" ? "The request failed." : message };
}

export function asText(value: string): string {
  return value;
}

export function looksLikeHTML(value: string): boolean {
  return /<[a-z][\s\S]*>/i.test(value);
}

export function firstFocusable(root: { querySelector: (sel: string) => unknown } | null): void {
  if (root === null) {
    return;
  }
  const node = root.querySelector("input, button, select, textarea, [href], [tabindex]:not([tabindex='-1'])");
  if (node !== null && typeof node === "object" && "focus" in node && typeof node.focus === "function") {
    node.focus();
  }
}
