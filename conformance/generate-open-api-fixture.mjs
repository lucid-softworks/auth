import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { betterAuth } from "better-auth";
import { openAPI } from "better-auth/plugins";

const repository = fileURLToPath(new URL("..", import.meta.url));
const auth = betterAuth({
  baseURL: "http://localhost:3000",
  secret: "O".repeat(32),
  plugins: [openAPI()],
});
const document = await auth.api.generateOpenAPISchema();
const fixture = {
  components: { schemas: document.components.schemas },
  paths: document.paths,
};
await writeFile(
  `${repository}/src/open_api/core.json`,
  `${JSON.stringify(fixture)}\n`,
);

const logoModule = await readFile(
  new URL("node_modules/better-auth/dist/plugins/open-api/logo.mjs", import.meta.url),
  "utf8",
);
const logo = logoModule.match(/const logo = `([\s\S]*?)`;\n/)?.[1];
if (!logo) throw new Error("could not extract the Better Auth OpenAPI logo");
await writeFile(
  `${repository}/src/open_api/favicon.txt`,
  `data:image/svg+xml;utf8,${encodeURIComponent(logo)}`,
);
