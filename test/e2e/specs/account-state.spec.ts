import { expect, test } from "@playwright/test";
import { login, loginReadOnly, visit } from "../helpers/session";

test("console can inspect, lock, unlock, require and clear password expiry", async ({ page }) => {
  await login(page);
  await visit(page, "/users/alice");
  const account = page.locator("#account-state-heading").locator("..");
  await expect(account).toContainText("Unlocked");
  const revisions: string[] = [];
  page.on("request", (request) => {
    if (request.method() === "POST" && /\/(lock|unlock|expire-password|clear-password-expiry)$/.test(request.url())) revisions.push(request.headers()["if-match"] ?? "");
  });
  await page.getByRole("button", { name: "Lock account", exact: true }).click();
  await expect(account).toContainText("Locked");
  await page.getByRole("button", { name: "Unlock account", exact: true }).click();
  await expect(account).toContainText("Unlocked");
  await page.getByRole("button", { name: "Require password change", exact: true }).click();
  await expect(account).toContainText("Password change required");
  await page.getByRole("button", { name: "Clear password expiry", exact: true }).click();
  await expect(account).toContainText("Password change not required");
  expect(revisions).toHaveLength(4);
  expect(revisions.every((revision) => /^".+"$/.test(revision))).toBe(true);
});

test("read-only session can inspect account state and cannot mutate it", async ({ page }) => {
  await loginReadOnly(page);
  await visit(page, "/users/alice");
  await expect(page.locator("#account-state-heading")).toBeVisible();
  for (const name of ["Lock account", "Unlock account", "Require password change", "Clear password expiry"]) {
    await expect(page.getByRole("button", { name, exact: true })).toBeDisabled();
  }
  await visit(page, "/tree");
  await page.getByRole("button", { name: "Expand ou=people" }).click();
  await page.getByRole("button", { name: "uid=alice", exact: true }).click();
  await expect(page.getByRole("button", { name: "Apply attribute change" })).toBeDisabled();
});

test("setting a password can require a change and clears password fields", async ({ page }) => {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("Emulation.setCPUThrottlingRate", { rate: 6 });
  await login(page);
  await visit(page, "/users/alice");
  let mustChange: unknown;
  await page.route("**/api/v1/users/alice/password", async (route) => {
    mustChange = route.request().postDataJSON().mustChange;
    await route.fulfill({ status: 204 });
  });
  await page.getByRole("button", { name: "Set password", exact: true }).click();
  await page.getByLabel("New password", { exact: true }).fill("discarded-draft-password");
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await page.getByRole("button", { name: "Set password", exact: true }).click();
  await expect(page.getByLabel("New password", { exact: true })).toHaveValue("");
  await page.getByLabel("New password", { exact: true }).fill("lab-example-password-12");
  await page.getByLabel("Confirm password", { exact: true }).fill("lab-example-password-12");
  await page.getByLabel("Require password change after setting password").check();
  await page.getByRole("button", { name: "Update password", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "Set password", exact: true })).not.toBeVisible();
  expect(mustChange).toBe(true);
  await expect(page.locator("#set-password")).toHaveValue("");
  await expect(page.locator("#set-confirm")).toHaveValue("");
});
