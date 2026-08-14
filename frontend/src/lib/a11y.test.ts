import assert from "node:assert/strict";
import { test } from "node:test";
import { asText, looksLikeHTML, mapProblem } from "./a11y.ts";

test("problem mapping covers conflict, outage, forbidden, and rate limit", () => {
  assert.equal(mapProblem({ status: 412, message: "x", revisionConflict: true }).message.includes("Refresh"), true);
  assert.match(mapProblem({ status: 503, message: "x", directoryUnavailable: true }).message, /outage/i);
  assert.equal(
    mapProblem({ status: 403, message: "x", forbidden: true, requiredScope: () => "audit:read" }).message,
    "Requires scope audit:read.",
  );
  assert.match(mapProblem({ status: 429, message: "x" }).message, /wait/i);
  assert.equal(mapProblem({ status: 400, message: "Filter is empty." }).role, "alert");
});

test("LDAP values containing HTML stay plain text", () => {
  const raw = '<img src=x onerror="alert(1)">cn-value';
  assert.equal(asText(raw), raw);
  assert.equal(looksLikeHTML(raw), true);
  assert.equal(looksLikeHTML("alice"), false);
});
