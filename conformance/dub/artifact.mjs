import { createRequire } from "node:module";
import * as rootExports from "@dub/better-auth";
import { dubAnalytics } from "@dub/better-auth";
import { describe, expect, test } from "vitest";
import {
  fakeDub,
  packageJson,
  packageLock,
  packageText,
} from "./helpers.mjs";

const require = createRequire(import.meta.url);

describe("@dub/better-auth@0.0.6 immutable artifact oracle", () => {
  test("pins package versions, registry integrity, hash, and effective runtimes", async () => {
    const pkg = await packageJson("@dub/better-auth");
    const lock = await packageLock();
    const locked = lock.packages["node_modules/@dub/better-auth"];

    expect(pkg.version).toBe("0.0.6");
    expect(pkg.devDependencies).toMatchObject({
      "better-auth": "^1.3.26",
      dub: "^0.66.5",
    });
    expect(pkg.dependencies).toEqual({ zod: "^3.24.4" });
    expect(pkg.exports).toEqual({
      ".": { import: "./dist/index.mjs", require: "./dist/index.cjs" },
      "./types": "./dist/index.d.mts",
    });
    expect(pkg.files).toEqual(["dist"]);
    expect(locked.resolved).toBe(
      "https://registry.npmjs.org/@dub/better-auth/-/better-auth-0.0.6.tgz",
    );
    expect(locked.integrity).toBe(
      "sha512-l7k1PVro6Ib6buBvB/ONlHl1xBH/nU0nbF9m0NawMYNeGhJwmw73JTg6HbhuBgfSRuzZUhI4jRhnldPzejWubg==",
    );
    expect({
      integrity: locked.integrity,
      sha1: "f485a7d08bdaee68284eff90b22a069b3b542c88",
    }).toEqual({
      integrity: "sha512-l7k1PVro6Ib6buBvB/ONlHl1xBH/nU0nbF9m0NawMYNeGhJwmw73JTg6HbhuBgfSRuzZUhI4jRhnldPzejWubg==",
      sha1: "f485a7d08bdaee68284eff90b22a069b3b542c88",
    });
    expect((await packageJson("better-auth")).version).toBe("1.7.2");
    expect((await packageJson("better-call")).version).toBe("1.4.0");
    expect((await packageJson("zod")).version).toBe("4.4.3");
    expect((await packageJson("dub")).version).toBe("0.66.5");
    expect((await packageJson("zod", "@dub/better-auth")).version).toBe("3.25.76");
  });

  test("exports only the server factory and rejects the documented client subpath", () => {
    expect(Object.keys(rootExports)).toEqual(["dubAnalytics"]);
    expect(dubAnalytics).toBeTypeOf("function");
    expect(() => require.resolve("@dub/better-auth/client")).toThrow(
      expect.objectContaining({ code: "ERR_PACKAGE_PATH_NOT_EXPORTED" }),
    );
    expect(require.resolve("@dub/better-auth/types")).toMatch(/dist\/index\.d\.mts$/);
  });

  test("pins declaration/runtime mismatches without fabricating client metadata", async () => {
    const declarations = await packageText("dist/index.d.mts");
    const runtime = await packageText("dist/index.mjs");
    const plugin = dubAnalytics({ dubClient: fakeDub() });

    expect(declarations).toContain("declare const dubAnalytics: (opts: DubConfig) => BetterAuthPlugin");
    expect(declarations).toContain("customLeadTrack?: (user: User, ctx: GenericEndpointContext)");
    expect(declarations).toContain("pkce?: boolean");
    expect(runtime).toContain('id: "dub"');
    expect(runtime).toContain('providerId: "dub"');
    expect(runtime).toContain("pkce: opts.oauth?.pkce === void 0 ? true : opts.oauth.pkce");
    expect(runtime).not.toContain("dub-analytics");
    expect(runtime).not.toMatch(/webhook|track\.sale|track\.update|retry|idempot|migration/i);
    expect(runtime).not.toContain("customerExternalId: opts");
    expect(runtime).not.toContain("clientSecret: ctx");
    expect(Object.keys(plugin)).toEqual(["id", "endpoints", "init"]);
    for (const absent of [
      "version",
      "schema",
      "migrations",
      "$ERROR_CODES",
      "client",
      "rateLimit",
    ]) {
      expect(absent in plugin).toBe(false);
    }
    expect(plugin.endpoints).not.toHaveProperty("oauth2CallbackDub");
  });
});
