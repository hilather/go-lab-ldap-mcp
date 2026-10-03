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
  await page.getByLabel("Attribute name").fill("description");
  await page.getByLabel("Values (one per line)").fill("Console edited container");
  await page.getByRole("button", { name: "Apply attribute change" }).click();
  await expect(page.locator("#inspector-attrs-heading").locator("..")).toContainText("Console edited container");

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

for (const action of ["move", "delete"] as const) {
  test(`tree ${action} uses the displayed revision and offers conflict refresh`, async ({ page }) => {
    await login(page);
    await visit(page, "/tree");
    await page.getByRole("button", { name: "Expand ou=people" }).click();
    await page.getByRole("button", { name: "uid=alice", exact: true }).click();
    await expect(page.locator("#inspector-attrs-heading")).toBeVisible();
    let entryReads = 0;
    await page.route("**/api/v1/entries?*", async (route) => {
      if (route.request().method() === "GET") { entryReads++; }
      if (route.request().method() === "DELETE") {
        await route.fulfill({ status: 412, contentType: "application/problem+json", body: JSON.stringify({ title: "revision conflict", code: "precondition_failed", status: 412 }) });
      } else await route.continue();
    });
    await page.route("**/api/v1/entries/move", (route) => route.fulfill({ status: 412, contentType: "application/problem+json", body: JSON.stringify({ title: "revision conflict", code: "precondition_failed", status: 412 }) }));
    if (action === "move") {
      await page.locator("#tree-move-to").fill("uid=alice-renamed,ou=people,dc=example,dc=test");
      await page.getByRole("button", { name: "Move entry" }).click();
    } else {
      await page.getByLabel("Type the exact DN to confirm").fill("uid=alice,ou=people,dc=example,dc=test");
      await page.getByRole("button", { name: "Delete entry", exact: true }).click();
    }
    await expect(page.getByRole("dialog", { name: "Revision conflict" })).toBeVisible();
    expect(entryReads).toBe(0);
    await page.getByRole("dialog").getByRole("button", { name: "Refresh", exact: true }).click();
    await expect.poll(() => entryReads).toBe(1);
  });
}
