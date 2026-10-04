import assert from "node:assert/strict";
import { test } from "node:test";
import {
  ariaSort,
  attributeMapFromRows,
  canSubmitGroupCreate,
  canSubmitMutation,
  canSubmitPassword,
  clearedPasswordFields,
  cycleErrorMessage,
  emptyGroupExplanation,
  emptyListMessage,
  exactIdConfirmed,
  firstForbiddenAttr,
  formFieldFromProblemPath,
  hasValidMember,
  ifMatchHeader,
  isAllowlistedUserAttr,
  isCycleField,
  isForbiddenUserAttr,
  isRevisionConflict,
  listQuery,
  membershipSummaryLabels,
  nextSortDir,
  passwordPolicyHints,
  passwordsMatch,
  quoteETag,
  sortGroups,
  sortUsers,
  mappedFormErrors,
  reservedCreateIdMessage,
  toUserSpecBody,
  uniqueMembers,
  userPatchAttributes,
  attrDuplicateKey,
  canonicalAttrType,
  legacyAliasPrimary,
  secondDescriptorPrimary,
  wouldEmptyGroup,
} from "./directory-model.ts";

test("read-only actor cannot submit create", () => {
  const denied = canSubmitMutation({ hasWrite: false, csrfPresent: true });
  assert.equal(denied.ok, false);
  assert.match(denied.reason, /directory:write/);
  assert.equal(canSubmitMutation({ hasWrite: true, csrfPresent: true }).ok, true);
  assert.equal(canSubmitMutation({ hasWrite: true, csrfPresent: false }).ok, false);
});

test("password mutations require the password scope", () => {
  const denied = canSubmitPassword({ hasPassword: false, csrfPresent: true });
  assert.equal(denied.ok, false);
  assert.match(denied.reason, /directory:password/);
});

test("password fields clear after success and failure", () => {
  const cleared = clearedPasswordFields();
  assert.equal(cleared.password, "");
  assert.equal(cleared.confirmPassword, "");
  assert.equal(passwordsMatch("secret", "secret"), true);
  assert.equal(passwordsMatch("secret", "other"), false);
});

test("password policy hints name scheme and stay non-secret", () => {
  const hints = passwordPolicyHints("PBKDF2-SHA256");
  assert.ok(hints.some((hint) => /server-side/i.test(hint)));
  assert.ok(hints.some((hint) => /12/.test(hint)));
  assert.ok(hints.some((hint) => /PBKDF2-SHA256/.test(hint)));
  assert.ok(hints.every((hint) => !/password=/.test(hint)));
});

test("mutations send a quoted revision If-Match", () => {
  assert.equal(quoteETag("abc"), '"abc"');
  assert.deepEqual(ifMatchHeader("deadbeef"), { "If-Match": '"deadbeef"' });
});

test("conflict is a refresh, not a silent overwrite", () => {
  assert.equal(isRevisionConflict(412, []), true);
  assert.equal(isRevisionConflict(409, [{ path: "id", code: "conflict" }]), false);
  assert.equal(isRevisionConflict(400, [{ path: "revision", code: "conflict" }]), true);
});

test("delete requires the exact user or group ID", () => {
  assert.equal(exactIdConfirmed("alice", "alice"), true);
  assert.equal(exactIdConfirmed("alice", "Alice"), false);
  assert.equal(exactIdConfirmed("alice", "alic"), false);
  assert.equal(exactIdConfirmed("", ""), false);
});

test("group create requires a valid initial member", () => {
  assert.equal(canSubmitGroupCreate([]).ok, false);
  assert.match(canSubmitGroupCreate([]).reason, /cannot be empty/);
  assert.equal(canSubmitGroupCreate([{ kind: "user", id: "   " }]).ok, false);
  assert.equal(canSubmitGroupCreate([{ kind: "user", id: "alice" }]).ok, true);
  assert.equal(hasValidMember([{ kind: "group", id: "staff" }]), true);
  assert.match(emptyGroupExplanation(), /fake member/i);
});

test("membership summaries count added, removed, unchanged, and rejected", () => {
  const labels = membershipSummaryLabels({
    added: [{ id: "a" }],
    removed: [{ id: "b" }, { id: "c" }],
    unchanged: [],
    rejected: [{ id: "d" }],
  });
  assert.deepEqual(labels, { added: 1, removed: 2, unchanged: 0, rejected: 1 });
});

test("cycle errors are clear and do not imply a write", () => {
  assert.equal(isCycleField("cycle", "members"), true);
  assert.equal(isCycleField("empty_group", "members"), false);
  assert.match(cycleErrorMessage(), /not changed/);
});

test("removing the last member would empty the group", () => {
  assert.equal(wouldEmptyGroup(1, 1), true);
  assert.equal(wouldEmptyGroup(2, 1), false);
});

test("server field paths attach to form controls", () => {
  assert.equal(formFieldFromProblemPath("id"), "id");
  assert.equal(formFieldFromProblemPath("password"), "password");
  assert.equal(formFieldFromProblemPath("attributes.sn"), "attributes");
  assert.equal(formFieldFromProblemPath("members.0"), "members");
  assert.equal(formFieldFromProblemPath("If-Match"), "revision");
});

test("allowlisted attributes reject operational and password names", () => {
  assert.equal(isAllowlistedUserAttr("mail"), true);
  assert.equal(isForbiddenUserAttr("userPassword"), true);
  assert.equal(isForbiddenUserAttr("nsAccountLock"), true);
  assert.equal(firstForbiddenAttr([{ name: "mail", value: "a@b" }, { name: "userPassword", value: "x" }]), "userPassword");
  assert.deepEqual(attributeMapFromRows([{ name: "sn", value: "Example" }, { name: "userPassword", value: "nope" }]), {
    sn: "Example",
  });
});

test("forbidden check strips options and resolves aliases like the server", () => {
  for (const name of [
    "userPassword;lang-en",
    "2.5.4.35",
    "2.5.4.35;x-a",
    "objectClass",
    "2.5.4.0",
    "1.2.3.4",
    "cn;lang-en",
    "commonName",
    "surname",
    "userid",
    "uid;x-a",
    "2.5.4.3",
    "authPassword",
  ]) {
    assert.equal(isForbiddenUserAttr(name), true, name);
  }
  for (const name of ["cn", " CN ", "sn", "uid", "mail", "mail;lang-en", "ou", "organizationalUnitName"]) {
    assert.equal(isForbiddenUserAttr(name), false, name);
  }
});

test("edit patch sends empty values for attributes removed from the form", () => {
  const patch = userPatchAttributes(
    [
      { name: "mail", value: "a@example.test" },
      { name: "sn", value: "Example" },
      { name: "telephoneNumber", value: "1" },
    ],
    [
      { name: "sn", value: "Example" },
      { name: "title", value: "Lab" },
    ],
  );
  assert.deepEqual(patch, {
    sn: "Example",
    title: "Lab",
    mail: "",
    telephoneNumber: "",
  });
  assert.equal(userPatchAttributes([], []), undefined);
});

test("create IDs cannot be the reserved route segment new", () => {
  assert.equal(reservedCreateIdMessage("new"), 'The ID "new" is reserved for the create page.');
  assert.equal(reservedCreateIdMessage("NEW"), 'The ID "new" is reserved for the create page.');
  assert.equal(reservedCreateIdMessage("alice"), undefined);
});

test("unmapped server fields still produce a form error", () => {
  const mapped = mappedFormErrors(
    [
      { path: "attributes.sn", message: "sn is required" },
      { path: "scope", message: "directory:write" },
    ],
    ["id", "uid", "password", "attributes"],
  );
  assert.deepEqual(mapped, [{ name: "attributes", message: "sn is required" }]);
  assert.deepEqual(mappedFormErrors([{ path: "limit", message: "too many" }], ["id", "members"]), []);
});

test("create body omits empty optional fields and never includes password aliases", () => {
  const spec = toUserSpecBody({
    id: " alice ",
    uid: "",
    enabled: true,
    password: "lab-example-password",
    attributes: [{ name: "sn", value: "Example" }],
  });
  assert.equal(spec.id, "alice");
  assert.equal("uid" in spec, false);
  assert.equal("enabled" in spec, false);
  assert.deepEqual(spec.attributes, { sn: "Example" });
  const disabled = toUserSpecBody({
    id: "bob",
    uid: "bob",
    enabled: false,
    password: "x",
    attributes: [],
  });
  assert.equal(disabled.enabled, false);
  assert.equal(disabled.uid, "bob");
});

test("list query omits blank search and cursor", () => {
  assert.deepEqual(listQuery({ pageSize: 25, q: "  ", cursor: "" }), { pageSize: 25 });
  assert.deepEqual(listQuery({ pageSize: 8, q: "al", cursor: "next" }), { pageSize: 8, q: "al", cursor: "next" });
});

test("sort applies to the current page only", () => {
  const users = sortUsers(
    [
      { id: "bob", uid: "bob", enabled: true },
      { id: "alice", uid: "alice", enabled: false },
    ],
    "id",
    "asc",
  );
  assert.deepEqual(
    users.map((u) => u.id),
    ["alice", "bob"],
  );
  const groups = sortGroups(
    [
      { id: "staff", memberCount: 2 },
      { id: "admins", memberCount: 1 },
    ],
    "memberCount",
    "asc",
  );
  assert.equal(groups[0]?.id, "admins");
  assert.equal(nextSortDir("id", "id", "asc"), "desc");
  assert.equal(ariaSort("id", "uid", "asc"), "none");
  assert.equal(ariaSort("id", "id", "desc"), "descending");
});

test("member search results stay unique and empty lists explain themselves", () => {
  const members = uniqueMembers([
    { kind: "user", id: "alice" },
    { kind: "user", id: "Alice" },
    { kind: "group", id: "staff" },
    { kind: "user", id: "  " },
  ]);
  assert.equal(members.length, 2);
  assert.match(emptyListMessage("users", true), /match/);
  assert.match(emptyListMessage("groups", false), /yet/);
});

test("second descriptors resolve like the server alias table", () => {
  assert.equal(canonicalAttrType("rfc822Mailbox"), "mail");
  assert.equal(canonicalAttrType("GN;lang-en"), "givenname");
  assert.equal(attrDuplicateKey("gn"), attrDuplicateKey("givenName"));
  assert.equal(attrDuplicateKey("mail;B;a"), "mail;a;b");
  assert.notEqual(attrDuplicateKey("mail"), attrDuplicateKey("mail;lang-en"));
  assert.equal(secondDescriptorPrimary("gn"), "givenName");
  assert.equal(secondDescriptorPrimary("rfc822Mailbox;x-a"), "mail");
  assert.equal(secondDescriptorPrimary("givenName"), undefined);
  assert.equal(legacyAliasPrimary("GN"), "givenName");
  assert.equal(legacyAliasPrimary("rfc822Mailbox"), "mail");
  for (const name of ["commonName", "userid", "organizationalUnitName", "mail"]) {
    assert.equal(legacyAliasPrimary(name), undefined, name);
  }
});

test("renaming a row to an alias does not also clear the primary", () => {
  const patch = userPatchAttributes(
    [{ name: "mail", value: "a@example.test" }],
    [{ name: "rfc822Mailbox", value: "b@example.test" }],
  );
  assert.deepEqual(patch, { rfc822Mailbox: "b@example.test" });
});
