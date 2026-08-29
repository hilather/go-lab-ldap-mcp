import { expect, test, type Locator, type Page } from "@playwright/test";
import { clearPasswordFields, login, visit } from "../helpers/session";

test.afterEach(async ({ page }) => {
  await clearPasswordFields(page);
});

function isWhite(color: string): boolean {
  return color === "rgb(255, 255, 255)" || color === "rgba(255, 255, 255, 1)";
}

function isTransparent(color: string): boolean {
  return color === "rgba(0, 0, 0, 0)" || color === "transparent";
}

async function paintedBackground(locator: Locator): Promise<string> {
  return locator.evaluate((el) => getComputedStyle(el).backgroundColor);
}

async function expectPaintedDark(locator: Locator): Promise<void> {
  const bg = await paintedBackground(locator);
  expect(isWhite(bg), `expected a dark painted surface, got ${bg}`).toBe(false);
  expect(isTransparent(bg), `expected a dark painted surface, got ${bg}`).toBe(false);
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
  const dialog = page.locator("dialog.confirm-dialog");
  await expect(dialog.getByRole("heading", { name: /Delete user/ })).toBeVisible();
  await expectPaintedDark(dialog);
  const backdrop = await page.evaluate(() => {
    const node = document.querySelector("dialog.confirm-dialog");
    return node === null ? "" : getComputedStyle(node, "::backdrop").backgroundColor;
  });
  expect(isWhite(backdrop), `dialog backdrop was ${backdrop}`).toBe(false);
  expect(isTransparent(backdrop), `dialog backdrop was ${backdrop}`).toBe(false);
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
  await expect(page.locator("#main .muted")).toContainText("No entries matched this search.");

  await visit(page, "/auth-test");
  await expectLeftoverChrome(page, page.locator("#main > form"));
  await expect(page.getByRole("button", { name: "Test bind" })).toHaveClass(/button-primary/);

  await visit(page, "/schema");
  await expectLeftoverChrome(page, page.locator("#main section").first());
  await page.getByLabel("Filter object classes").fill("zzzz");
  await expect(page.locator("#main .muted")).toContainText("No object classes match this search.");

  await visit(page, "/audit");
  await expectLeftoverChrome(page, page.locator("#main > form"));
  await expect(page.getByRole("button", { name: "Apply filters" })).toHaveClass(/button-primary/);
  await page.getByLabel("Action").fill("no.such.action");
  await page.getByRole("button", { name: "Apply filters" }).click();
  await expect(page.locator("#main .muted")).toContainText("No audit events match these filters.");

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
