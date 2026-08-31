import { describe, expect, test, vi } from "vitest";
import {
  CHALLENGE_TTL,
  DEFAULT_DIFFICULTY,
  decodePoWChallenge,
  encodePoWSolution,
  sentinel,
  solvePoWChallenge,
  verifyPoWSolution,
} from "@better-auth/infra";
import { sentinelClient } from "@better-auth/infra/client";
import { sentinelNativeClient } from "@better-auth/infra/native";
import { infraText, packageJson, packageLock } from "./infra-email.helpers.mjs";

describe("@better-auth/infra@0.4.3 Sentinel root/browser/native oracle", () => {
  test("pins the immutable package and exact Sentinel root exports", async () => {
    const pkg = await packageJson("@better-auth/infra");
    const locked = (await packageLock()).packages["node_modules/@better-auth/infra"];
    expect(pkg.version).toBe("0.4.3");
    expect(locked.integrity).toBe(
      "sha512-wQAdFoFxD/waZYHyF9hKIf8jAnWxVK0R2S28Q/4vCrXWCDKBn5ZVZb1Sy8UHcmbnr1p7xuscBZJTPoFfE6y89A==",
    );
    expect({ sha1: "f20fabec398194cae23ccc35c324eccf8796e4db" }).toEqual({
      sha1: "f20fabec398194cae23ccc35c324eccf8796e4db",
    });
    expect({
      CHALLENGE_TTL,
      DEFAULT_DIFFICULTY,
      decodePoWChallenge,
      encodePoWSolution,
      sentinel,
      solvePoWChallenge,
      verifyPoWSolution,
    }).toEqual(expect.objectContaining({ CHALLENGE_TTL: 60, DEFAULT_DIFFICULTY: 18 }));
  });

  test("declares only server lifecycle hooks and database hooks", () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const plugin = sentinel({ apiKey: "fixture-key" });
    expect(Object.keys(plugin)).toEqual(["id", "init", "hooks"]);
    expect(plugin.id).toBe("sentinel");
    expect(plugin.hooks.before).toHaveLength(5);
    expect(plugin.hooks.after).toHaveLength(3);
    const initialized = plugin.init({ getPlugin: () => null });
    expect(Object.keys(initialized.options.databaseHooks.user)).toEqual(["create", "update"]);
    expect(Object.keys(initialized.options.databaseHooks.session.create)).toEqual([
      "before",
      "after",
    ]);
  });

  test("solves, encodes, decodes, and verifies the published PoW shape", async () => {
    const challenge = { nonce: "oracle", difficulty: 4, timestamp: 1, ttl: 60 };
    const solution = await solvePoWChallenge(challenge);
    expect(solution.nonce).toBe("oracle");
    expect(await verifyPoWSolution(solution.nonce, solution.counter, 4)).toBe(true);
    const encoded = encodePoWSolution(solution);
    expect(JSON.parse(atob(encoded))).toEqual(solution);
    expect(decodePoWChallenge(btoa(JSON.stringify(challenge)))).toEqual(challenge);
    expect(decodePoWChallenge("not-base64-json")).toBeNull();
  });

  test("pins server routes, fallbacks, privacy primitives, and event projection", async () => {
    const source = await infraText("dist/index.mjs");
    for (const fragment of [
      'const STALE_ACCOUNT_BLOCK_ERROR = {',
      'const IDENTIFICATION_COOKIE_NAME = "__infra-rid"',
      'const CACHE_TTL_MS = 6e4',
      'const CACHE_MAX_SIZE = 1e3',
      '"/security/check"',
      '`/security/is-blocked?',
      '"/security/track-failed-login"',
      '"/security/clear-failed-attempts"',
      '"/security/pow/generate"',
      '"/security/impossible-travel"',
      '"/security/free-trial-abuse/reserve"',
      '"/security/breached-passwords"',
      '"/security/stale-user"',
      '"/security/resolve-policy"',
      '"/events/track"',
      'await hmacSha256Hex(conn.apiKey, password)',
      'const prefix = hash.substring(0, 5)',
      'eventType: "security_signal"',
      'eventType: "security_check"',
      'return { action: "allow" }',
      'return { isStale: false }',
    ]) expect(source).toContain(fragment);
  });

  test("pins exact email and phone validation contracts", async () => {
    const source = await infraText("dist/index.mjs");
    for (const fragment of [
      'const GMAIL_LIKE_DOMAINS =',
      '"googlemail.com"',
      'policyId: "email_validity"',
      '$kv("/email/validate"',
      'message: "Invalid email"',
      '"/phone-number/send-otp"',
      '"/phone-number/verify"',
      '"/sign-in/phone-number"',
      '"/phone-number/request-password-reset"',
      '"/phone-number/reset-password"',
      'message: "Invalid phone number"',
    ]) expect(source).toContain(fragment);
  });

  test("publishes browser and native fetch plugins in exact order", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ expiresAt: null }))));
    const plugins = [sentinelClient({ identifyUrl: "https://kv.example/projects/test" }),
      sentinelNativeClient({ identifyUrl: "https://kv.example/projects/test" })];
    for (const plugin of plugins) {
      expect(plugin.id).toBe("sentinel");
      expect(plugin.fetchPlugins.map(({ id, name }) => ({ id, name }))).toEqual([
        { id: "sentinel-fingerprint", name: "sentinel-fingerprint" },
        { id: "sentinel-pow-solver", name: "sentinel-pow-solver" },
      ]);
      const requestHook = plugin.fetchPlugins[1].hooks.onRequest;
      expect(await requestHook({ body: "" })).not.toHaveProperty("_originalBody");
      expect(await requestHook({ body: '{"email":"person@example.com"}' }))
        .toHaveProperty("_originalBody", '{"email":"person@example.com"}');
    }
  });

  test("pins browser and native fingerprint, retry, storage, scheduling, and RNG quirks", async () => {
    const browser = await infraText("dist/client.mjs");
    const native = await infraText("dist/native.mjs");
    const shared = await infraText("dist/pow-retry-BWDJUT8X.mjs");
    for (const fragment of [
      'credentials: "include"',
      'const MAX_POW_CHALLENGE_ROUNDS = 2',
      'const body = req._originalBody',
      'screenResolution:',
      'canvas:',
      'webgl:',
      'audio:',
    ]) expect(`${browser}\n${shared}`).toContain(fragment);
    for (const fragment of [
      'im.runAfterInteractions',
      'queueMicrotask',
      'better-auth.infra.sentinel.visitorId',
      'c.getRandomValues',
      'await import("expo-crypto")',
      'throw new Error("[@better-auth/infra] No secure RNG available',
      'clientRuntime: "react-native"',
      'const NATIVE_IDENTIFY_CONFIDENCE = .52',
      'const NATIVE_IDENTIFY_CONTEXT_URL = "react-native://identify"',
      'incognito: false',
    ]) expect(native).toContain(fragment);
    expect(native).not.toContain('credentials: "include"');
    expect(native).not.toContain("Math.random");
  });
});
