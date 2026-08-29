import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { clearPasswordFields, login, visit } from "../helpers/session";

test.afterEach(async ({ page }) => {
  // Best-effort UI cleanup only. Trace zip redaction runs in global teardown
  // after Playwright has written attachments.
  await clearPasswordFields(page);
});

async function expectNoSeriousViolations(page: Parameters<typeof login>[0]): Promise<void> {
  const results = await new AxeBuilder({ page }).include("main").analyze();
  const serious = results.violations.filter((v) => v.impact === "critical" || v.impact === "serious");
  expect(serious, JSON.stringify(serious, null, 2)).toEqual([]);
}

test("core forms pass automated accessibility checks", async ({ page }) => {
  await page.goto("/login");
  await expectNoSeriousViolations(page);

  await login(page);
  await visit(page, "/search");
  await expect(page.getByRole("heading", { name: "Search" })).toBeVisible();
  await expectNoSeriousViolations(page);

  await visit(page, "/auth-test");
  await expect(page.getByRole("heading", { name: "Bind test" })).toBeVisible();
  await expectNoSeriousViolations(page);

  await visit(page, "/users/alice");
  await expect(page.getByRole("heading", { name: /alice/i })).toBeVisible();
  await page.getByRole("button", { name: /^Delete$/ }).click();
  await expect(page.getByRole("heading", { name: /Delete user/ })).toBeVisible();
  await expectNoSeriousViolations(page);

  await page.keyboard.press("Escape");
  await visit(page, "/schema");
  await expect(page.getByRole("heading", { name: "Schema" })).toBeVisible();
  await expectNoSeriousViolations(page);

  await visit(page, "/tree");
  await expect(page.locator("#main")).toBeVisible();
  await expectNoSeriousViolations(page);
});
