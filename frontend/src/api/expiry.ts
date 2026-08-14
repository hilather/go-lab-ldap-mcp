// Session expiry and idle refresh are signaled in-memory only.

let onExpired: (() => void) | undefined;
let onActivity: (() => void) | undefined;

export function setSessionExpiredHandler(handler: (() => void) | undefined): void {
  onExpired = handler;
}

export function notifySessionExpired(): void {
  onExpired?.();
}

export function setSessionActivityHandler(handler: (() => void) | undefined): void {
  onActivity = handler;
}

export function notifySessionActivity(): void {
  onActivity?.();
}
