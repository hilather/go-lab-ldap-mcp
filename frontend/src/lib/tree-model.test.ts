import assert from "node:assert/strict";
import { test } from "node:test";
import { exactIdConfirmed } from "./directory-model.ts";
import {
  canExpandTreeNode,
  childDN,
  displayMembershipLabel,
  entryKind,
  isProtectedTreeDN,
  isSensitiveAttr,
  membershipFromGroupEntry,
  nodeMatchesFilter,
  parentDN,
  rdnOf,
  shouldShowNode,
  userIdFromEntry,
  writeOnlyPasswordRow,
} from "./tree-model.ts";

test("entry kind maps object classes used by the inspector", () => {
  assert.equal(entryKind(["domain"], { isSuffix: true }), "suffix");
  assert.equal(entryKind(["organizationalUnit"]), "ou");
  assert.equal(entryKind(["inetOrgPerson", "person"]), "user");
  assert.equal(entryKind(["groupOfNames"]), "group");
  assert.equal(entryKind(["domain"]), "domain");
});

test("expand is offered when subordinates are unknown, as on native", () => {
  assert.equal(canExpandTreeNode({ hasChildren: false, loaded: false, childCount: 0 }), true);
  assert.equal(canExpandTreeNode({ hasChildren: false, loaded: true, childCount: 0 }), false);
  assert.equal(canExpandTreeNode({ hasChildren: false, loaded: true, childCount: 0, isExpanded: true }), true);
  assert.equal(canExpandTreeNode({ hasChildren: true, loaded: false, childCount: 0 }), true);
  assert.equal(canExpandTreeNode({ hasChildren: false, loaded: true, childCount: 2 }), true);
});

test("filter matches RDN or DN and keeps ancestors of matches", () => {
  const alice = { dn: "uid=alice,ou=people,dc=example,dc=test", rdn: "uid=alice" };
  const people = { dn: "ou=people,dc=example,dc=test", rdn: "ou=people" };
  assert.equal(nodeMatchesFilter(alice, "alice"), true);
  assert.equal(nodeMatchesFilter(alice, "ou=people,dc=example"), true);
  assert.equal(nodeMatchesFilter(people, "alice"), false);
  const children = new Map([[people.dn, [alice]]]);
  assert.equal(shouldShowNode(people, "alice", children), true);
  assert.equal(shouldShowNode(people, "nope", children), false);
});

test("child DN is built under the selected parent unless a full DN is typed", () => {
  assert.equal(
    childDN("ou=labtree", "ou=people,dc=example,dc=test"),
    "ou=labtree,ou=people,dc=example,dc=test",
  );
  assert.equal(
    childDN("ou=labtree,ou=groups,dc=example,dc=test", "ou=people,dc=example,dc=test"),
    "ou=labtree,ou=groups,dc=example,dc=test",
  );
  assert.equal(childDN("", "ou=people,dc=example,dc=test"), "");
  assert.equal(rdnOf("uid=alice,ou=people,dc=example,dc=test"), "uid=alice");
  assert.equal(parentDN("uid=alice,ou=people,dc=example,dc=test"), "ou=people,dc=example,dc=test");
});

test("user id and group members come from allowlisted attributes", () => {
  assert.equal(
    userIdFromEntry({
      dn: "uid=alice,ou=people,dc=example,dc=test",
      objectClasses: ["inetOrgPerson"],
      attributes: [{ name: "uid", value: "alice" }],
    }),
    "alice",
  );
  assert.deepEqual(
    membershipFromGroupEntry({
      dn: "cn=staff,ou=groups,dc=example,dc=test",
      objectClasses: ["groupOfNames"],
      attributes: [
        { name: "member", value: "uid=alice,ou=people,dc=example,dc=test" },
        { name: "uniqueMember", value: "uid=bob,ou=people,dc=example,dc=test" },
      ],
    }),
    ["uid=alice,ou=people,dc=example,dc=test", "uid=bob,ou=people,dc=example,dc=test"],
  );
  assert.equal(displayMembershipLabel({ id: "staff", dn: "cn=staff,ou=groups,dc=example,dc=test" }), "cn=staff");
});

test("write-only password row is not sourced from entry attributes", () => {
  const row = writeOnlyPasswordRow("user");
  assert.ok(row);
  assert.equal(row.name, "userPassword");
  assert.equal(isSensitiveAttr("userPassword"), true);
  assert.equal(
    writeOnlyPasswordRow("ou"),
    undefined,
  );
  const leaked = membershipFromGroupEntry({
    dn: "uid=alice,ou=people,dc=example,dc=test",
    objectClasses: ["inetOrgPerson"],
    attributes: [{ name: "userPassword", value: "secret-must-not-become-a-pill" }],
  });
  assert.deepEqual(leaked, []);
});

test("protected DNs are suffix, people, and groups only from known suffixes", () => {
  const suffixes = ["dc=example,dc=test"];
  assert.equal(isProtectedTreeDN("dc=example,dc=test", suffixes), true);
  assert.equal(isProtectedTreeDN("ou=people,dc=example,dc=test", suffixes), true);
  assert.equal(isProtectedTreeDN("ou=groups,dc=example,dc=test", suffixes), true);
  assert.equal(isProtectedTreeDN("ou=labtree,ou=people,dc=example,dc=test", suffixes), false);
});

test("delete still requires the exact DN", () => {
  assert.equal(exactIdConfirmed("ou=labtree,ou=people,dc=example,dc=test", "ou=labtree,ou=people,dc=example,dc=test"), true);
  assert.equal(exactIdConfirmed("ou=labtree,ou=people,dc=example,dc=test", "ou=labtree"), false);
});
