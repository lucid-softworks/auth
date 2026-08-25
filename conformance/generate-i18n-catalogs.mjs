import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import * as localeExports from "@better-auth/i18n/locales";

const repository = new URL("../", import.meta.url);
const output = new URL("src/i18n/catalogs.json", repository);

function sortedEntries(object) {
  return Object.fromEntries(
    Object.entries(object)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([key, value]) => [
        key,
        typeof value === "object" && value !== null
          ? sortedEntries(value)
          : value,
      ]),
  );
}

await mkdir(fileURLToPath(new URL("./", output)), { recursive: true });
await writeFile(output, JSON.stringify(sortedEntries(localeExports)), "utf8");
