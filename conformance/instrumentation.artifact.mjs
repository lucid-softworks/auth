import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { expect } from "vitest";

const files = [
  "node_modules/@better-auth/core/dist/instrumentation/attributes.mjs",
  "node_modules/@better-auth/core/dist/instrumentation/tracer.mjs",
  "node_modules/@better-auth/core/dist/instrumentation/api.mjs",
  "node_modules/@better-auth/core/dist/instrumentation/noop.mjs",
  "node_modules/@better-auth/core/dist/instrumentation/pure.index.mjs",
  "node_modules/better-auth/dist/api/dispatch.mjs",
  "node_modules/better-auth/dist/api/index.mjs",
  "node_modules/better-auth/dist/db/with-hooks.mjs",
  "node_modules/@better-auth/core/dist/db/adapter/factory.mjs",
];

export async function instrumentationArtifact() {
  const entries = await Promise.all(
    files.map(async (file) => {
      const source = await readFile(new URL(file, import.meta.url), "utf8");
      return {
        file,
        sha256: createHash("sha256").update(source).digest("hex"),
        source,
      };
    }),
  );
  return entries;
}

export function assertPinnedInstrumentationArtifact(entries) {
  const source = entries.map((entry) => entry.source).join("\n");
  expect(source).toContain('const INSTRUMENTATION_SCOPE = "better-auth"');
  expect(source).toContain('const INSTRUMENTATION_VERSION = "1.7.2"');
  expect(source).toContain("db incrementOne ${model}");
  expect(source).toContain("db updateMany.before ${model}");
  expect(source).toContain("middleware ${m.path} ${plugin.id}");
  expect(source).toContain("onRequest ${plugin.id}");
  expect(source).toContain("onResponse ${plugin.id}");
  expect(source).not.toMatch(/sampler|exporter|propagator|telemetryEnabled/i);
}
