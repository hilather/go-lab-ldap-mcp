import { expect, type Page } from "@playwright/test";
import { adminToken, readToken } from "./secrets";

export async function login(page: Page, token = adminToken): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Management token").fill(token);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
}

export async function visit(page: Page, dest: string): Promise<void> {
  // Client-side navigation keeps the in-memory CSRF secret. Full page.goto
  // reloads the tab and drops it (documented incomplete browser session).
  const nav = page.getByRole("navigation", { name: "Primary" });
  const named: Record<string, string> = {
    "/": "Dashboard",
    "/users": "Users",
    "/groups": "Groups",
    "/search": "Search",
    "/tree": "Directory",
    "/auth-test": "Bind test",
    "/schema": "Schema",
    "/audit": "Audit",
    "/reset": "Reset",
    "/export": "Export",
    "/diagnostics": "Diagnostics",
  };
  const label = named[dest];
  if (label !== undefined) {
    await nav.getByRole("link", { name: label, exact: true }).click();
    return;
  }
  if (dest === "/users/new") {
    await nav.getByRole("link", { name: "Users", exact: true }).click();
    await page.getByRole("link", { name: "Create user" }).click();
    return;
  }
  if (dest.startsWith("/users/")) {
    const id = decodeURIComponent(dest.slice("/users/".length));
    await nav.getByRole("link", { name: "Users", exact: true }).click();
    await page.getByRole("link", { name: id, exact: true }).click();
    return;
  }
  throw new Error(`no in-app route helper for ${dest}`);
}

export async function loginReadOnly(page: Page): Promise<void> {
  await login(page, readToken);
}

export async function storageDump(page: Page): Promise<string> {
  return page.evaluate(() => {
    const local: Record<string, string> = {};
    const session: Record<string, string> = {};
    for (let i = 0; i < localStorage.length; i += 1) {
      const key = localStorage.key(i);
      if (key !== null) {
        local[key] = localStorage.getItem(key) ?? "";
      }
    }
    for (let i = 0; i < sessionStorage.length; i += 1) {
      const key = sessionStorage.key(i);
      if (key !== null) {
        session[key] = sessionStorage.getItem(key) ?? "";
      }
    }
    return JSON.stringify({ local, session, href: location.href });
  });
}

export async function clearPasswordFields(page: Page): Promise<void> {
  await page
    .locator('input[type="password"]')
    .evaluateAll((els) => {
      for (const el of els) {
        if (el instanceof HTMLInputElement) {
          el.value = "";
        }
      }
    })
    .catch(() => undefined);
}
