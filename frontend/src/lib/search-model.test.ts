import assert from "node:assert/strict";
import { test } from "node:test";
import {
  emptySearchForm,
  entryToLDIF,
  isAllowlistedSearchAttr,
  isForbiddenSearchAttr,
  redactedAttrNames,
  requestedSearchAttributes,
  searchBody,
  searchFieldError,
  searchProblemMessage,
  toggleAttr,
  validSearchScope,
} from "./search-model.ts";

test("search form does not include a default filter that would auto-run", () => {
  const form = emptySearchForm();
  assert.equal(form.filter, "");
  assert.equal(form.scope, "sub");
  assert.deepEqual(form.attributes, []);
});

test("forbidden search attributes cannot be requested", () => {
  assert.equal(isForbiddenSearchAttr("userPassword"), true);
  assert.equal(isForbiddenSearchAttr("aci"), true);
  assert.equal(isForbiddenSearchAttr("*"), true);
  assert.equal(isAllowlistedSearchAttr("uid"), true);
  assert.deepEqual(requestedSearchAttributes(["uid", "userPassword", "aci", "mail"]), {
    sent: ["uid", "mail"],
    blocked: ["userPassword", "aci"],
  });
  assert.deepEqual(toggleAttr(["uid"], "userPassword"), ["uid"]);
  assert.deepEqual(toggleAttr(["uid"], "mail"), ["uid", "mail"]);
});

test("search body omits empty optional fields and blocked attributes", () => {
  const body = searchBody(
    {
      base: " ou=people,dc=example,dc=test ",
      scope: "one",
      filter: "(uid=alice)",
      pageSize: 25,
      attributes: ["uid", "userPassword"],
    },
    "cursor-1",
  );
  assert.deepEqual(body, {
    base: "ou=people,dc=example,dc=test",
    scope: "one",
    filter: "(uid=alice)",
    attributes: ["uid"],
    pageSize: 25,
    cursor: "cursor-1",
  });
  const defaults = searchBody(emptySearchForm(), "");
  assert.deepEqual(defaults, { filter: "", pageSize: 50 });
});

test("filter and boundary errors are actionable", () => {
  assert.match(searchFieldError("filter", "empty", "x"), /does not run/);
  assert.match(searchFieldError("filter", "over_broad", "x"), /too broad/);
  assert.match(searchFieldError("base", "invalid_dn", "x"), /valid DN/);
  assert.match(searchFieldError("base", "forbidden", "x"), /managed suffix/);
  const mapped = searchProblemMessage([{ path: "filter", code: "unbalanced", message: "nope" }], "fallback");
  assert.equal(mapped.field, "filter");
  assert.match(mapped.message, /unbalanced/);
});

test("LDIF copy skips forbidden attributes and flattens HTML-looking values", () => {
  const ldif = entryToLDIF({
    dn: "uid=alice,ou=people,dc=example,dc=test",
    attributes: [
      { name: "uid", value: "alice" },
      { name: "cn", value: "<img src=x onerror=alert(1)>" },
      { name: "userPassword", value: "secret-must-not-copy" },
    ],
  });
  assert.match(ldif, /^dn: uid=alice/);
  assert.match(ldif, /cn: <img src=x onerror=alert\(1\)>/);
  assert.doesNotMatch(ldif, /userPassword|secret-must-not-copy/);
});

test("redaction indicators name requested attributes that were omitted", () => {
  assert.deepEqual(redactedAttrNames(["uid", "mail"], [{ name: "uid", value: "alice" }]), ["mail"]);
  assert.equal(validSearchScope("children"), "children");
  assert.equal(validSearchScope("nope"), "sub");
});
