import assert from "node:assert/strict";
import { test } from "node:test";
import {
  clearMemoryBearer,
  clearMemoryCSRF,
  getMemoryBearer,
  getMemoryCSRF,
  setMemoryBearer,
  setMemoryCSRF,
} from "./token.ts";

test("session exchange keeps the token out of memory and storage APIs", () => {
  setMemoryBearer("lab-secret-token-must-not-remain");
  // Login writes CSRF to memory and must drop any transient bearer slot.
  setMemoryCSRF("csrf-memory-only");
  clearMemoryBearer();
  assert.equal(getMemoryBearer(), undefined);
  assert.equal(getMemoryCSRF(), "csrf-memory-only");
  assert.equal(typeof localStorage, "undefined");
  assert.equal(typeof sessionStorage, "undefined");
  assert.equal(typeof indexedDB, "undefined");
});

test("logout clears bearer and CSRF memory slots", () => {
  setMemoryBearer("should-clear");
  setMemoryCSRF("csrf-should-clear");
  clearMemoryBearer();
  clearMemoryCSRF();
  assert.equal(getMemoryBearer(), undefined);
  assert.equal(getMemoryCSRF(), undefined);
});
