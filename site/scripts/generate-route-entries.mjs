import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { splitDocument } from "../lib/docs.mjs";

const site = resolve(import.meta.dirname, "..");
const root = resolve(site, "..");
const dist = join(site, "dist");
const entry = join(dist, "index.html");
const configs = JSON.parse(readFileSync(join(site, "content.config.json"), "utf8"));
const routes = configs.flatMap((config) =>
  splitDocument(config, readFileSync(join(root, config.source), "utf8")).map((page) => page.path),
);
const legacyRoutes = [
  "/installation",
  "/frameworks",
  "/production",
  "/database-id-migration",
  "/mssql",
  "/compatibility",
];

for (const route of [...routes, ...legacyRoutes]) {
  if (route === "/") continue;
  const destination = join(dist, route.slice(1), "index.html");
  mkdirSync(dirname(destination), { recursive: true });
  copyFileSync(entry, destination);
}

copyFileSync(entry, join(dist, "404.html"));
writeFileSync(join(dist, "routes.json"), `${JSON.stringify(routes, null, 2)}\n`);
console.log(`Generated ${routes.length} documentation route entries and ${legacyRoutes.length} redirects.`);
