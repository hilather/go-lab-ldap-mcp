import assert from "node:assert/strict";
import { test } from "node:test";
import {
  auditQuery,
  bindOutcomePresentation,
  bindRateLimitMessage,
  canSubmitBindTest,
  canSubmitExport,
  canSubmitReset,
  clearedBindPassword,
  exportConfirmNeeded,
  filterNamed,
  isResetInProgress,
  looksSecret,
  moveIndex,
  resetPollInterval,
  safeAuditField,
} from "./ops-model.ts";

test("bind test requires password scope and CSRF", () => {
  assert.equal(canSubmitBindTest({ hasPassword: false, csrfPresent: true }).ok, false);
  assert.equal(canSubmitBindTest({ hasPassword: true, csrfPresent: false }).ok, false);
  assert.equal(canSubmitBindTest({ hasPassword: true, csrfPresent: true }).ok, true);
  assert.equal(clearedBindPassword().password, "");
});

test("bind failure does not distinguish unknown user from wrong password", () => {
  const result = bindOutcomePresentation("invalid_credentials");
  assert.match(result.detail, /does not distinguish/i);
  assert.doesNotMatch(result.title, /unknown|not found/i);
  assert.doesNotMatch(result.detail, /user does not exist|incorrect password/i);
  assert.match(bindRateLimitMessage(), /wait/i);
});

test("schema filter and keyboard index stay in range", () => {
  const items = filterNamed([{ name: "inetOrgPerson" }, { name: "groupOfNames" }], "inet");
  assert.deepEqual(
    items.map((item) => item.name),
    ["inetOrgPerson"],
  );
  assert.equal(moveIndex(0, 1, 3), 1);
  assert.equal(moveIndex(2, 1, 3), 2);
  assert.equal(moveIndex(-1, 1, 3), 0);
});

test("audit actor and target drop secret-looking values", () => {
  assert.equal(safeAuditField("token:admin"), "token:admin");
  assert.equal(safeAuditField("session:abcd"), "session:abcd");
  assert.equal(safeAuditField("Bearer lab-admin-token-value"), "[redacted]");
  assert.equal(safeAuditField("password=super-secret-value"), "[redacted]");
  assert.equal(looksSecret("Cookie=labldap_session=abc"), true);
  assert.deepEqual(auditQuery({ pageSize: 25, action: "reset", actor: " token:admin ", cursor: "" }), {
    pageSize: 25,
    action: "reset",
    actor: "token:admin",
  });
});

test("reset cannot submit without scope, exact name, and current revision", () => {
  const current = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  assert.equal(
    canSubmitReset({
      hasReset: false,
      csrfPresent: true,
      name: "example-lab",
      revision: current,
      currentRevision: current,
      inProgress: false,
    }).ok,
    false,
  );
  assert.equal(
    canSubmitReset({
      hasReset: true,
      csrfPresent: true,
      name: "",
      revision: current,
      currentRevision: current,
      inProgress: false,
    }).ok,
    false,
  );
  assert.equal(
    canSubmitReset({
      hasReset: true,
      csrfPresent: true,
      name: "example-lab",
      revision: "wrong",
      currentRevision: current,
      inProgress: false,
    }).ok,
    false,
  );
  assert.equal(
    canSubmitReset({
      hasReset: true,
      csrfPresent: true,
      name: "example-lab",
      revision: current,
      currentRevision: current,
      inProgress: true,
    }).ok,
    false,
  );
  assert.equal(
    canSubmitReset({
      hasReset: true,
      csrfPresent: true,
      name: "example-lab",
      revision: current,
      currentRevision: current,
      inProgress: false,
    }).ok,
    true,
  );
  assert.equal(isResetInProgress("Resetting"), true);
  assert.equal(isResetInProgress("Ready"), false);
  assert.equal(resetPollInterval("Verifying"), 1000);
  assert.equal(resetPollInterval("Ready"), false);
});

test("export omitSecrets defaults to confirmation when secrets would be included", () => {
  assert.equal(canSubmitExport({ hasExport: false }).ok, false);
  assert.equal(canSubmitExport({ hasExport: true }).ok, true);
  assert.equal(exportConfirmNeeded(true), false);
  assert.equal(exportConfirmNeeded(false), true);
});
