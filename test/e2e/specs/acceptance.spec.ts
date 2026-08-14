import { expect, test } from "@playwright/test";
import { adminToken, bindPassword, compiledRevision, scenarioName } from "../helpers/secrets";
import { clearPasswordFields, login, loginReadOnly, storageDump, visit } from "../helpers/session";

test.afterEach(async ({ page }) => {
  await clearPasswordFields(page);
});

test("admin session completes the product acceptance scenario", async ({ page }) => {
  await login(page, adminToken);
  await expect(page.getByRole("heading", { name: "Directory status" })).toBeVisible();
  await expect(page.getByText("The directory is ready for operator workflows.")).toBeVisible();

  const stored = await storageDump(page);
  expect(stored).not.toContain(adminToken);
  expect(stored.toLowerCase()).not.toContain("csrf");

  await visit(page, "/users");
  await expect(page.getByRole("link", { name: "alice" })).toBeVisible();

  await visit(page, "/groups");
  await expect(page.getByRole("link", { name: "staff" })).toBeVisible();

  await visit(page, "/search");
  await page.getByLabel("Filter").fill("(uid=alice)");
  await expect(page.getByRole("heading", { name: "Results" })).toHaveCount(0);
  await page.getByRole("button", { name: "Search" }).click();
  await expect(page.getByText("uid=alice,ou=people,dc=example,dc=test")).toBeVisible();
  await page.getByText("uid=alice,ou=people,dc=example,dc=test").click();
  await expect(page.getByText("<img src=x onerror=alert(1)>Alice")).toBeVisible();
  await expect(page.locator('img[src="x"]')).toHaveCount(0);

  await visit(page, "/auth-test");
  await page.getByLabel("Identity").fill("alice");
  await page.getByLabel("Password").fill(bindPassword);
  await page.getByRole("button", { name: "Test bind" }).click();
  await expect(page.getByRole("heading", { name: "Success" })).toBeVisible();
  await expect(page.getByLabel("Password")).toHaveValue("");

  await visit(page, "/schema");
  await expect(page.getByRole("heading", { name: "Root DSE" })).toBeVisible();
  await page.getByLabel("Filter object classes").fill("inet");
  await page.getByRole("option", { name: "inetOrgPerson" }).click();
  await expect(page.getByText("STRUCTURAL")).toBeVisible();

  await visit(page, "/audit");
  await expect(page.getByText(/in-memory audit ring/i)).toBeVisible();
  await expect(page.getByRole("cell", { name: "session.create" }).first()).toBeVisible();

  await visit(page, "/export");
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "Download LDIF" }).click(),
  ]);
  expect(download.suggestedFilename()).toMatch(/\.ldif$/);

  await visit(page, "/reset");
  await page.getByLabel("Scenario name").fill(scenarioName);
  await page.getByLabel("Expected revision").fill(compiledRevision);
  await page.getByRole("button", { name: "Start soft reset" }).click();
  await expect(page.getByRole("status")).toContainText(/Reset completed/, { timeout: 10_000 });

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "LabLDAP sign in" })).toBeVisible();
});

test("read-only session cannot open write workflows", async ({ page }) => {
  await loginReadOnly(page);
  await visit(page, "/users");
  await expect(page.locator("#main").getByText("Requires scope directory:write.")).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Primary" }).getByText("Requires scope audit:read.")).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Primary" }).getByText("Requires scope lab:reset.")).toBeVisible();
});
