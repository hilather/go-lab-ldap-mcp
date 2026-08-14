import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
if (pkg.packageManager !== "pnpm@10.14.0") {
  console.error("frontend packageManager pin drifted:", pkg.packageManager);
  process.exit(1);
}
if (!pkg.engines?.node?.startsWith(">=22.12")) {
  console.error("frontend engines.node pin drifted:", pkg.engines?.node);
  process.exit(1);
}
if (!String(pkg.dependencies?.react ?? "").startsWith("19.2.")) {
  console.error("frontend react pin drifted:", pkg.dependencies?.react);
  process.exit(1);
}
if (!String(pkg.dependencies?.["react-dom"] ?? "").startsWith("19.2.")) {
  console.error("frontend react-dom pin drifted:", pkg.dependencies?.["react-dom"]);
  process.exit(1);
}
console.log("frontend pin lint ok");
