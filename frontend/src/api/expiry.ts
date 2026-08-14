// Session expiry is signaled in-memory only. Do not persist the reason.

let onExpired: (() => void) | undefined;

export function setSessionExpiredHandler(handler: (() => void) | undefined): void {
  onExpired = handler;
}

export function notifySessionExpired(): void {
  onExpired?.();
}
