import { expect, test } from "@playwright/test";
import { clearPasswordFields, login, visit } from "../helpers/session";

test.afterEach(async ({ page }) => {
  await clearPasswordFields(page);
});

test("operator can browse the tree, create an OU and user at an explicit DN, then delete with confirm", async ({
  page,
}) => {
  await login(page);
  await visit(page, "/tree");
  await expect(page.getByRole("heading", { name: "Directory tree" })).toBeVisible();
  await expect(page.getByLabel("Managed suffix")).toContainText("dc=example,dc=test");

  await page.getByLabel("Object class").selectOption("organizationalUnit");
  await page.locator("#tree-create-dn").fill("ou=labtree,ou=people,dc=example,dc=test");
  await page.getByRole("button", { name: "Create entry" }).click();
  await expect(page.getByRole("status")).toContainText("Created ou=labtree,ou=people,dc=example,dc=test");

  await page.locator("#tree-user-id").fill("tree-svc");
  await page.locator("#tree-user-dn").fill("uid=tree-svc,ou=labtree,ou=people,dc=example,dc=test");
  await page.locator("#tree-user-password").fill("tree-svc-pass-12");
  await page.getByRole("button", { name: "Create user at DN" }).click();
  await expect(page.getByRole("status")).toContainText("Created user tree-svc");

  await page.locator("#tree-move-from").fill("ou=labtree,ou=people,dc=example,dc=test");
  await page.locator("#tree-move-to").fill("ou=labtree-moved,ou=people,dc=example,dc=test");
  await page.getByRole("button", { name: "Move entry" }).click();
  await expect(page.getByRole("status")).toContainText("Moved to ou=labtree-moved,ou=people,dc=example,dc=test");

  await page.locator("#tree-delete-dn").fill("ou=labtree-moved,ou=people,dc=example,dc=test");
  await page.getByLabel("Type the exact DN to confirm").fill("ou=labtree-moved,ou=people,dc=example,dc=test");
  await page.getByLabel("Recursive").check();
  await page.getByRole("button", { name: "Delete entry" }).click();
  await expect(page.getByRole("status")).toContainText("Deleted entry.");
});
