import { expect, test } from "@playwright/test";
import { redactTree } from "../helpers/redact.mjs";
import { secretsToMask } from "../helpers/secrets";
import { clearPasswordFields, login } from "../helpers/session";

test.afterEach(async ({ page }, info) => {
  await clearPasswordFields(page);
  if (info.status !== info.expectedStatus) {
    await redactTree(info.outputDir, secretsToMask());
  }
});

test("dashboard stays up and names a directory outage", async ({ page, request }) => {
  test.skip(process.env.LABLDAP_E2E_BASE_URL !== undefined, "outage injection is mock-only");
  await request.post("/__e2e/outage", { data: { enabled: true } });
  await login(page);
  await expect(page.getByRole("heading", { name: "Directory outage" })).toBeVisible();
  await expect(page.getByText(/directory reads failed/i)).toBeVisible();
  await request.post("/__e2e/outage", { data: { enabled: false } });
});
