import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { redactTree } from "./helpers/redact.mjs";
import { secretsToMask } from "./helpers/secrets";

export default async function globalTeardown(): Promise<void> {
  const root = dirname(fileURLToPath(import.meta.url));
  await redactTree(join(root, "test-results"), secretsToMask());
  await redactTree(join(root, "playwright-report"), secretsToMask());
}
