import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dist = join(root, "dist");

await mkdir(dist, { recursive: true });
await writeFile(
  join(dist, "index.html"),
  `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>LabLDAP</title>
  </head>
  <body>
    <p>LabLDAP frontend placeholder. The React application lands in T-095.</p>
  </body>
</html>
`,
  "utf8",
);
console.log("wrote frontend/dist/index.html");
