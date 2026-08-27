import { describe, expect, test } from "vitest";
import { dash } from "@better-auth/infra";
import { infraText, packageJson, packageLock } from "./infra-email.helpers.mjs";

describe("@better-auth/infra@0.4.3 Dash substrate oracle", () => {
  test("pins the immutable package and peer runtime", async () => {
    const pkg = await packageJson("@better-auth/infra");
    const lock = await packageLock();
    const locked = lock.packages["node_modules/@better-auth/infra"];

    expect(pkg.version).toBe("0.4.3");
    expect(locked.resolved).toBe(
      "https://registry.npmjs.org/@better-auth/infra/-/infra-0.4.3.tgz",
    );
    expect(locked.integrity).toBe(
      "sha512-wQAdFoFxD/waZYHyF9hKIf8jAnWxVK0R2S28Q/4vCrXWCDKBn5ZVZb1Sy8UHcmbnr1p7xuscBZJTPoFfE6y89A==",
    );
    expect({ sha1: "f20fabec398194cae23ccc35c324eccf8796e4db" }).toEqual({
      sha1: "f20fabec398194cae23ccc35c324eccf8796e4db",
    });
    expect((await packageJson("better-auth")).version).toBe("1.7.1");
    expect((await packageJson("@better-fetch/fetch")).version).toBe("1.3.1");
  });

  test("resolves exact falsey URL/key and nullish timeout/retry defaults", () => {
    const defaults = dash().options;
    expect(defaults).toMatchObject({
      apiUrl: "https://dash.better-auth.com",
      kvUrl: "https://kv.better-auth.com",
      apiKey: "",
      apiOptions: { timeout: 3000 },
      kvOptions: {
        timeout: 1000,
        retry: { attempts: 2, baseDelay: 400, maxDelay: 600 },
      },
    });

    const zeroes = dash({
      apiUrl: "",
      kvUrl: "",
      apiKey: "",
      apiOptions: { timeout: 0 },
      apiTimeout: 9,
      kvOptions: {
        timeout: 0,
        retry: { attempts: 0, baseDelay: 0, maxDelay: 0 },
      },
      kvTimeout: 8,
    });
    expect(zeroes.id).toBe("dash");
    expect(zeroes.version).toBe("0.4.3");
    expect(zeroes.options).toMatchObject({
      apiUrl: "https://dash.better-auth.com",
      kvUrl: "https://kv.better-auth.com",
      apiKey: "",
      apiOptions: { timeout: 0 },
      kvOptions: {
        timeout: 0,
        retry: { attempts: 0, baseDelay: 0, maxDelay: 0 },
      },
    });
  });

  test("pins the private JWT, client, and identification boundary", async () => {
    const source = [
      await infraText("dist/index.mjs"),
      await infraText("dist/crypto-SmxL66Tk.mjs"),
    ].join("\n");
    for (const fragment of [
      '"user-agent": INFRA_USER_AGENT',
      '"x-api-key": options.apiKey',
      'if (options.apiKey) headers["x-api-key"] = options.apiKey',
      'const JWKS_CACHE_TTL_MS = 9e5',
      'jwtVerify(jwsFromHeader, remoteJWKs, { maxTokenAge: "5m" })',
      'Date.now() - issuedAt < JTI_CHECK_GRACE_PERIOD_SECONDS * 1e3',
      '"/api/auth/check-jti"',
      'const IDENTIFICATION_COOKIE_NAME = "__infra-rid"',
      'const CACHE_TTL_MS = 6e4',
      'const CACHE_MAX_SIZE = 1e3',
    ]) {
      expect(source).toContain(fragment);
    }
  });

  test("installs identification as one global hook without owning its route", () => {
    const plugin = dash();
    expect(plugin.hooks.before).toHaveLength(1);
    expect(plugin.hooks.after).toHaveLength(4);
    expect(Object.values(plugin.endpoints).map((endpoint) => endpoint.path)).not.toContain(
      "/identify/:requestId",
    );
  });
});
