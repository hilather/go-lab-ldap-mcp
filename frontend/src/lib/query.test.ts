import assert from "node:assert/strict";
import { test } from "node:test";
import {
  clearDirectoryQueryData,
  clearSessionQueryData,
  createAppQueryClient,
  invalidateAfterReset,
  queryKeys,
} from "./query.ts";

test("logout and expiry clear directory query data", () => {
  const client = createAppQueryClient();
  client.setQueryData(queryKeys.directory.baseline, { match: true });
  client.setQueryData(queryKeys.users.detail("alice"), { id: "alice" });
  client.setQueryData(queryKeys.session, { id: "sess-1" });

  clearDirectoryQueryData(client);
  assert.equal(client.getQueryData(queryKeys.directory.baseline), undefined);
  assert.equal(client.getQueryData(queryKeys.users.detail("alice")), undefined);
  assert.deepEqual(client.getQueryData(queryKeys.session), { id: "sess-1" });

  clearSessionQueryData(client);
  assert.equal(client.getQueryData(queryKeys.session), undefined);
});

test("reset completion invalidates baseline, users, groups, capabilities, and audit", async () => {
  const client = createAppQueryClient();
  client.setQueryData(queryKeys.directory.baseline, { match: true });
  client.setQueryData(queryKeys.directory.capabilities, { requiredOK: true });
  client.setQueryData(queryKeys.directory.audit, []);
  client.setQueryData(queryKeys.users.detail("alice"), { id: "alice" });
  client.setQueryData(queryKeys.groups.detail("staff"), { id: "staff" });
  await invalidateAfterReset(client);
  assert.equal(client.getQueryState(queryKeys.directory.baseline)?.isInvalidated, true);
  assert.equal(client.getQueryState(queryKeys.users.detail("alice"))?.isInvalidated, true);
  assert.equal(client.getQueryState(queryKeys.groups.detail("staff"))?.isInvalidated, true);
});
