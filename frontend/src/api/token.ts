// In-memory only. T-096 exchanges a token for a session cookie, then clears
// this slot. Never write bearer or CSRF secrets to Web Storage or the URL.

let bearer: string | undefined;
let csrf: string | undefined;

export function setMemoryBearer(token: string | undefined): void {
  bearer = token === "" ? undefined : token;
}

export function getMemoryBearer(): string | undefined {
  return bearer;
}

export function clearMemoryBearer(): void {
  bearer = undefined;
}

export function setMemoryCSRF(token: string | undefined): void {
  csrf = token === "" ? undefined : token;
}

export function getMemoryCSRF(): string | undefined {
  return csrf;
}

export function clearMemoryCSRF(): void {
  csrf = undefined;
}
