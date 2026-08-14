import assert from "node:assert/strict";
import { test } from "node:test";
import { clearDirectoryQueryData, clearSessionQueryData, createAppQueryClient, queryKeys } from "./query.ts";

test("logout and expiry clear directory query data", () => {
  const client = createAppQueryClient();
  client.setQueryData(queryKeys.directory.baseline, { match: true });
  client.setQueryData([...queryKeys.directory.all, "users"], [{ id: "alice" }]);
  client.setQueryData(queryKeys.session, { id: "sess-1" });

  clearDirectoryQueryData(client);
  assert.equal(client.getQueryData(queryKeys.directory.baseline), undefined);
  assert.equal(client.getQueryData([...queryKeys.directory.all, "users"]), undefined);
  assert.deepEqual(client.getQueryData(queryKeys.session), { id: "sess-1" });

  clearSessionQueryData(client);
  assert.equal(client.getQueryData(queryKeys.session), undefined);
});
