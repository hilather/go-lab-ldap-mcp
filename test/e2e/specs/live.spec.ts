import { execFileSync } from "node:child_process";
import { expect, test } from "@playwright/test";
import { bindPassword } from "../helpers/secrets";
import { clearPasswordFields, login, visit } from "../helpers/session";

test.skip(process.env.LABLDAP_E2E_LIVE !== "1", "requires the isolated real-engine Compose harness");

test.afterEach(async ({ page }) => {
  await clearPasswordFields(page);
});

function searchLDAP(dn: string): string {
  // Credentials remain in a restricted file, never argv or browser storage.
  return execFileSync("ldapsearch", [
    "-x", "-H", process.env.LABLDAP_E2E_LDAP_URL!, "-D", "cn=Directory Manager",
    "-y", process.env.LABLDAP_E2E_DM_PASSWORD_FILE!, "-b", dn, "-s", "base", "(objectClass=*)", "description",
   ], { timeout: 10_000, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, LDAPTLS_CACERT: process.env.LABLDAP_E2E_CA_FILE, LDAPTLS_REQCERT: "demand" } });
}

// searchLDAPStatus returns ldapsearch's exit status for a base search. It
// must have thrown with a numeric status; success or a missing status is
// reported as -1 so only an exact LDAP result code can satisfy a caller.
function searchLDAPStatus(dn: string): number {
  try {
    searchLDAP(dn);
  } catch (err) {
    const status = (err as { status?: unknown }).status;
    return typeof status === "number" ? status : -1;
  }
  return 0;
}

const LDAP_NO_SUCH_OBJECT = 32;

test("live native console account and structured-entry workflows affect the real directory", async ({ page }) => {
  await login(page);
  await visit(page, "/users/alice");
  const account = page.locator("#account-state-heading").locator("..");
  await expect(account).toContainText("Unlocked");
  await page.getByRole("button", { name: "Lock account", exact: true }).click();
  await expect(account).toContainText("Locked");
  await page.getByRole("button", { name: "Unlock account", exact: true }).click();
  await expect(account).toContainText("Unlocked");
  await page.getByRole("button", { name: "Require password change", exact: true }).click();
  await expect(account).toContainText("Password change required");
  await page.getByRole("button", { name: "Clear password expiry", exact: true }).click();
  await expect(account).toContainText("Password change not required");
  await page.getByRole("button", { name: "Set password", exact: true }).click();
  await page.getByLabel("New password", { exact: true }).fill(bindPassword);
  await page.getByLabel("Confirm password", { exact: true }).fill(bindPassword);
  await page.getByLabel("Require password change after setting password").check();
  await page.getByRole("button", { name: "Update password", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "Set password", exact: true })).not.toBeVisible();
  await expect(account).toContainText("Password change required");
  await expect(page.locator("#set-password")).toHaveValue("");
  await page.getByRole("button", { name: "Clear password expiry", exact: true }).click();
  await expect(account).toContainText("Password change not required");

  await visit(page, "/tree");
  await page.getByRole("button", { name: "ou=people", exact: true }).click();
  await page.getByLabel("RDN", { exact: true }).fill("ou=browser-smoke");
  await page.locator("form").filter({ has: page.locator("#tree-create-rdn") }).getByRole("button", { name: "Create child", exact: true }).click();
  await expect(page.locator("#main").getByRole("status")).toContainText("Created ou=browser-smoke");
  await page.getByRole("button", { name: "ou=browser-smoke", exact: true }).click();
  await page.getByLabel("Attribute name").fill("description");
  await page.getByLabel("Values (one per line)").fill("Live browser edit");
  await page.getByRole("button", { name: "Apply attribute change", exact: true }).click();
  await expect(page.locator("#inspector-attrs-heading").locator("..")).toContainText("Live browser edit");
  expect(searchLDAP("ou=browser-smoke,ou=people,dc=example,dc=test")).toContain("description: Live browser edit");
  await page.locator("#tree-move-to").fill("ou=browser-moved,ou=people,dc=example,dc=test");
  await page.getByRole("button", { name: "Move entry", exact: true }).click();
  await expect(page.locator("#main").getByRole("status")).toContainText("Moved to ou=browser-moved");
  expect(searchLDAP("ou=browser-moved,ou=people,dc=example,dc=test")).toContain("description: Live browser edit");
  await page.getByLabel("Type the exact DN to confirm").fill("ou=browser-moved,ou=people,dc=example,dc=test");
  await page.getByRole("button", { name: "Delete entry", exact: true }).click();
  await expect(page.locator("#main").getByRole("status")).toContainText("Deleted entry.");
  // The real directory must no longer hold the entry: exactly noSuchObject,
  // not a bind, TLS, or timeout failure.
  expect(searchLDAPStatus("ou=browser-moved,ou=people,dc=example,dc=test")).toBe(LDAP_NO_SUCH_OBJECT);
});
