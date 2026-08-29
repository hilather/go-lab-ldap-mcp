import { expect, test, type Locator, type Page } from "@playwright/test";
import { clearPasswordFields, login, visit } from "../helpers/session";

test.afterEach(async ({ page }) => {
  await clearPasswordFields(page);
});

const TOKEN_SURFACES = new Set([
  "rgb(11, 12, 14)",
  "rgb(18, 19, 23)",
  "rgb(24, 26, 31)",
]);

async function paintedBackground(locator: Locator): Promise<string> {
  return locator.evaluate((el) => getComputedStyle(el).backgroundColor);
}

async function expectPaintedDark(locator: Locator): Promise<void> {
  const bg = await paintedBackground(locator);
  expect(TOKEN_SURFACES.has(bg), `expected a Directory token surface, got ${bg}`).toBe(true);
}

async function expectPlex(locator: Locator): Promise<void> {
  const family = await locator.evaluate((el) => getComputedStyle(el).fontFamily);
  expect(family).toMatch(/IBM Plex/);
}

async function expectLeftoverChrome(page: Page, surface: Locator): Promise<void> {
  await expect(surface).toBeVisible();
  await expectPaintedDark(surface);
  await expectPlex(surface);
}

test("leftover operator pages use Directory chrome", async ({ page }) => {
  await page.goto("/login");
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
  await expect(page.locator("main.login img.brand-mark")).toBeVisible();
  await expect(page.locator(".login-card")).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign in" })).toHaveClass(/button-primary/);
  await expectPaintedDark(page.locator("main.login"));
  await expectLeftoverChrome(page, page.locator(".login-card"));

  await login(page);

  await visit(page, "/");
  await expectLeftoverChrome(page, page.locator(".status-card"));

  await visit(page, "/users");
  await expectLeftoverChrome(page, page.locator("#main > form"));
  await expect(page.getByRole("button", { name: "Search" })).toHaveClass(/button-primary/);
  await expect(page.getByRole("link", { name: "Create user" })).toHaveClass(/button-primary/);

  await visit(page, "/users/new");
  await expectLeftoverChrome(page, page.locator("#main > form"));
  await expect(page.getByRole("button", { name: "Create user" })).toHaveClass(/button-primary/);

  await visit(page, "/users/alice");
  await expectLeftoverChrome(page, page.locator("#main section").first());
  await expect(page.locator("#main .membership-pill").first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Save changes" })).toHaveClass(/button-primary/);
  const deleteUser = page.getByRole("button", { name: /^Delete$/ });
  await expect(deleteUser).toHaveClass(/button-danger/);
  await deleteUser.click();
  const dialog = page.getByRole("dialog", { name: "Delete user" });
  await expect(dialog.getByRole("heading", { name: /Delete user/ })).toBeVisible();
  await expectPaintedDark(dialog);
  const backdrop = await page.evaluate(() => {
    const node = document.querySelector("dialog.confirm-dialog[open]");
    return node === null ? "" : getComputedStyle(node, "::backdrop").backgroundColor;
  });
  expect(backdrop).toBe("rgba(11, 12, 14, 0.72)");
  await page.keyboard.press("Escape");

  await visit(page, "/groups");
  await expectLeftoverChrome(page, page.locator("#main > form"));
  await expect(page.getByRole("button", { name: "Search" })).toHaveClass(/button-primary/);
  await expect(page.getByRole("link", { name: "Create group" })).toHaveClass(/button-primary/);

  await visit(page, "/groups/new");
  await expectLeftoverChrome(page, page.locator("#main > form"));
  await expect(page.getByRole("button", { name: "Create group" })).toHaveClass(/button-primary/);

  await visit(page, "/groups/staff");
  await expect(page.getByRole("heading", { name: /staff/i })).toBeVisible();
  await expectLeftoverChrome(page, page.locator("#main section").first());
  await expect(page.getByRole("button", { name: "Delete group" })).toHaveClass(/button-danger/);

  await visit(page, "/search");
  await expectLeftoverChrome(page, page.locator("#main > form"));
  await expect(page.getByRole("button", { name: "Search" })).toHaveClass(/button-primary/);
  await expectPaintedDark(page.locator("#search-page-size"));
  await page.getByLabel("Filter").fill("(uid=nosuch)");
  await page.getByRole("button", { name: "Search" }).click();
  await expect(page.getByText("No entries matched this search.")).toBeVisible();

  await visit(page, "/auth-test");
  await expectLeftoverChrome(page, page.locator("#main > form"));
  await expect(page.getByRole("button", { name: "Test bind" })).toHaveClass(/button-primary/);

  await visit(page, "/schema");
  await expectLeftoverChrome(page, page.locator("#main section").first());
  await page.getByLabel("Filter object classes").fill("zzzz");
  await expect(page.getByText("No object classes match this search.")).toBeVisible();

  await visit(page, "/audit");
  await expectLeftoverChrome(page, page.locator("#main > form"));
  await expect(page.getByRole("button", { name: "Apply filters" })).toHaveClass(/button-primary/);
  await page.getByLabel("Action").fill("no.such.action");
  await page.getByRole("button", { name: "Apply filters" }).click();
  await expect(page.getByText("No audit events match these filters.")).toBeVisible();

  await visit(page, "/reset");
  await expectLeftoverChrome(page, page.locator("#main > form"));
  await expect(page.getByRole("button", { name: "Start soft reset" })).toHaveClass(/button-primary/);

  await visit(page, "/export");
  await expectLeftoverChrome(page, page.locator("#main > form"));
  await expect(page.getByRole("button", { name: "Download LDIF" })).toHaveClass(/button-primary/);

  await visit(page, "/diagnostics");
  await expect(page.getByRole("heading", { name: "Component status" })).toBeVisible();
  await expectLeftoverChrome(page, page.locator("#main section").first());
});
