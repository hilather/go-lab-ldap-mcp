import { expect, test } from "@playwright/test";
import { clearPasswordFields, login, visit } from "../helpers/session";

test.afterEach(async ({ page }) => {
  await clearPasswordFields(page);
});

test("operator can browse the directory, inspect a user, then create, move, and delete a child OU", async ({
  page,
}) => {
  const ifMatch = { move: "", delete: "" };
  page.on("request", (req) => {
    const url = req.url();
    if (req.method() === "POST" && url.includes("/api/v1/entries/move")) {
      ifMatch.move = req.headers()["if-match"] ?? "";
    }
    if (req.method() === "DELETE" && url.includes("/api/v1/entries")) {
      ifMatch.delete = req.headers()["if-match"] ?? "";
    }
  });

  await login(page);
  await visit(page, "/tree");

  const directory = page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Directory", exact: true });
  await expect(directory).toHaveAttribute("aria-current", "page");

  const header = page.locator(".app-header");
  await expect(header).toContainText(/expires in \d+[mhd]|expired/);
  await expect(header).not.toContainText(/T\d{2}:\d{2}:\d{2}/);
  await expect(header).toContainText("directory:write");
  await expect(page.getByRole("heading", { name: "Granted scopes" })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Create user at exact DN" })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Create group at exact DN" })).toHaveCount(0);
  await expect(page.getByText("Create users and groups on their own pages. The tree is for browsing and acting on a selected DN.")).toBeVisible();

  await page.getByRole("button", { name: "Expand ou=people" }).click();
  await page.getByRole("button", { name: "uid=alice", exact: true }).click();
  await expect(page.locator("#main").getByRole("heading", { level: 1 })).toContainText("uid=alice");
  await expect(page.locator(".inspector-dn")).toContainText("uid=alice,ou=people,dc=example,dc=test");
  await expect(page.locator("#inspector-membership-heading").locator("..")).toContainText("cn=staff");

  await page.getByRole("button", { name: "ou=people", exact: true }).click();
  await page.locator("#tree-create-rdn").fill("ou=labtree");
  await page
    .locator("form")
    .filter({ has: page.locator("#tree-create-rdn") })
    .getByRole("button", { name: "Create child" })
    .click();
  await expect(page.locator("#main").getByRole("status")).toContainText("Created ou=labtree,ou=people,dc=example,dc=test");
  await expect(page.getByRole("button", { name: "ou=labtree", exact: true })).toBeVisible();

  await page.getByRole("button", { name: "ou=labtree", exact: true }).click();
  await page.locator("#tree-move-to").fill("ou=labtree-moved,ou=people,dc=example,dc=test");
  await page.getByRole("button", { name: "Move entry" }).click();
  await expect(page.locator("#main").getByRole("status")).toContainText("Moved to ou=labtree-moved,ou=people,dc=example,dc=test");

  await page.getByLabel("Type the exact DN to confirm").fill("ou=labtree-moved,ou=people,dc=example,dc=test");
  await page.getByLabel("Recursive").check();
  await page.getByRole("button", { name: "Delete entry" }).click();
  await expect(page.locator("#main").getByRole("status")).toContainText("Deleted entry.");
  expect(ifMatch.move).toMatch(/^"/);
  expect(ifMatch.delete).toMatch(/^"/);
});
