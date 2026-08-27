import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { isAPIError } from "better-auth/api";
import { beforeEach, describe, expect, test, vi } from "vitest";

const platform = { OS: "android" };
const browser = { openAuthSessionAsync: vi.fn() };

vi.mock("react-native", () => ({
  AppState: { addEventListener: vi.fn(() => ({ remove: vi.fn() })) },
  Platform: platform,
}));
vi.mock("expo-constants", () => ({
  default: { expoConfig: { scheme: "oracle" }, platform: { scheme: "fallback" } },
}));
vi.mock("expo-linking", () => ({
  createURL: vi.fn((path, options) => `${options?.scheme || "oracle"}://${path}`),
}));
vi.mock("expo-network", () => ({
  addNetworkStateListener: vi.fn(() => ({ remove: vi.fn() })),
}));
vi.mock("expo-web-browser", () => browser);

import { expo } from "@better-auth/expo";
import * as clientExports from "@better-auth/expo/client";
import * as pluginExports from "@better-auth/expo/plugins";

const require = createRequire(import.meta.url);
const packageRoot = new URL("node_modules/@better-auth/expo/", import.meta.url);

async function packageJson() {
  return JSON.parse(await readFile(new URL("package.json", packageRoot), "utf8"));
}

async function packageLock() {
  return JSON.parse(await readFile(new URL("package-lock.json", import.meta.url), "utf8"));
}

function memoryStorage() {
  const values = new Map();
  return {
    values,
    getItem: (key) => values.get(key) ?? null,
    getItemAsync: async (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    setItemAsync: async (key, value) => values.set(key, value),
    deleteItemAsync: async (key) => values.delete(key),
  };
}

function endpointContext(query) {
  return {
    input: {
      query,
      returnHeaders: true,
      context: {
        baseURL: "https://auth.example/api/auth",
        createAuthCookie: (name, attributes) => ({
          name: `better-auth.${name}`,
          attributes,
        }),
        secret: "expo-oracle-secret-at-least-32-bytes",
      },
    },
  };
}

async function endpointError(endpoint, query) {
  try {
    await endpoint(endpointContext(query).input);
  } catch (error) {
    return error;
  }
  throw new Error("expected endpoint to reject");
}

describe("@better-auth/expo@1.7.1 immutable artifact", () => {
  test("pins registry metadata, exact exports, dependencies, and package surface", async () => {
    const pkg = await packageJson();
    const lock = await packageLock();
    const locked = lock.packages["node_modules/@better-auth/expo"];

    expect(pkg.version).toBe("1.7.1");
    expect(locked.resolved).toBe("https://registry.npmjs.org/@better-auth/expo/-/expo-1.7.1.tgz");
    expect(locked.integrity).toBe("sha512-Cnq6Zx58p3c9wGslQMv7Q1gkLxRqs3WMxQ0YamNdxp0430fzY/bsYwchT+5SXotm+yw088krkiiBqrVAU4tymw==");
    expect({ sha1: "faf8b98b8edad797e5baaeaa55f65690bc407d33" }).toEqual({
      sha1: "faf8b98b8edad797e5baaeaa55f65690bc407d33",
    });
    expect(pkg.dependencies).toEqual({
      "@better-fetch/fetch": "1.3.1",
      "better-call": "1.4.0",
      "zod": "^4.3.6",
    });
    expect(Object.keys(pkg.exports)).toEqual([".", "./client", "./plugins"]);
    expect(Object.keys(clientExports).sort()).toEqual([
      "expoClient", "getCookie", "getSetCookie", "hasBetterAuthCookies",
      "normalizeCookieName", "parseSetCookieHeader", "setupExpoFocusManager",
      "setupExpoOnlineManager", "storageAdapter",
    ].sort());
    expect(Object.keys(pluginExports)).toEqual(["lastLoginMethodClient"]);
    expect(() => require.resolve("@better-auth/expo/server")).toThrow(
      expect.objectContaining({ code: "ERR_PACKAGE_PATH_NOT_EXPORTED" }),
    );
  });

  test("publishes the exact server descriptor and only disableOriginOverride", () => {
    const options = { disableOriginOverride: true };
    const plugin = expo(options);
    expect(Object.keys(plugin)).toEqual([
      "id", "version", "init", "onRequest", "hooks", "endpoints", "options",
    ]);
    expect(plugin).toMatchObject({ id: "expo", version: "1.7.1", options });
    expect(Object.keys(plugin.endpoints)).toEqual(["expoAuthorizationProxy"]);
    const endpoint = plugin.endpoints.expoAuthorizationProxy;
    expect(endpoint.path).toBe("/expo-authorization-proxy");
    expect(endpoint.options.method).toBe("GET");
    expect(endpoint.options.metadata).toEqual({ scope: "server" });
    for (const absent of ["$ERROR_CODES", "client", "cookies", "migrations", "rateLimit", "schema"])
      expect(plugin).not.toHaveProperty(absent);
  });
});

describe("@better-auth/expo@1.7.1 server behavior", () => {
  beforeEach(() => {
    vi.unstubAllEnvs();
  });

  test("adds only exp:// in development", () => {
    vi.stubEnv("NODE_ENV", "development");
    expect(expo().init({})).toEqual({ options: { trustedOrigins: ["exp://"] } });
    vi.stubEnv("NODE_ENV", "production");
    expect(expo().init({})).toEqual({ options: { trustedOrigins: [] } });
  });

  test("bridges only expo-origin and never replaces Origin", async () => {
    const plugin = expo();
    const bridged = await plugin.onRequest(new Request("https://auth.example/sign-in", {
      headers: { "expo-origin": "oracle://" },
    }), {});
    expect(bridged.request.headers.get("origin")).toBe("oracle://");

    for (const name of ["expoOrigin", "x-expo-origin", "x-electron-origin"])
      expect(await plugin.onRequest(new Request("https://auth.example", {
        headers: { [name]: "oracle://" },
      }), {})).toBeUndefined();

    const existing = new Request("https://auth.example", {
      headers: { origin: "https://web.example", "expo-origin": "oracle://" },
    });
    expect(await plugin.onRequest(existing, {})).toBeUndefined();
    expect(existing.headers.get("origin")).toBe("https://web.example");
    expect(await expo({ disableOriginOverride: true }).onRequest(
      new Request("https://auth.example", { headers: { "expo-origin": "oracle://" } }), {},
    )).toBeUndefined();
  });

  test("proxy rejects unsafe targets with exact API errors", async () => {
    const endpoint = expo().endpoints.expoAuthorizationProxy;
    for (const authorizationURL of [
      "not-a-url",
      "http://provider.example/auth?state=x",
      "https://auth.example/callback?state=x",
      "https://provider.example/auth?state=x#fragment",
      "https://provider.example/auth?state=x#",
    ]) {
      const error = await endpointError(endpoint, { authorizationURL });
      expect(isAPIError(error)).toBe(true);
      expect(error).toMatchObject({
        statusCode: 400,
        body: { message: "Invalid authorizationURL" },
      });
    }
    const missingState = await endpointError(endpoint, {
      authorizationURL: "https://provider.example/auth",
    });
    expect(missingState).toMatchObject({
      statusCode: 400,
      body: { message: "Unexpected error" },
    });
  });

  test("proxy sets the exact raw or signed state cookie before redirect", async () => {
    const endpoint = expo().endpoints.expoAuthorizationProxy;
    const raw = endpointContext({
      authorizationURL: "https://provider.example/auth?state=provider-state",
      oauthState: "persisted-state",
    });
    const rawResult = await endpoint(raw.input);
    expect(rawResult.response).toMatchObject({ statusCode: 302 });
    expect(rawResult.headers.get("location")).toBe(
      "https://provider.example/auth?state=provider-state",
    );
    expect(rawResult.headers.get("set-cookie")).toContain(
      "better-auth.oauth_state=persisted-state; Max-Age=600",
    );

    const signed = endpointContext({
      authorizationURL: "https://provider.example/auth?state=provider-state",
    });
    const signedResult = await endpoint(signed.input);
    expect(signedResult.headers.get("location")).toBe(
      "https://provider.example/auth?state=provider-state",
    );
    expect(signedResult.headers.get("set-cookie")).toMatch(
      /^better-auth\.state=provider-state\.[^;]+; Max-Age=300/,
    );
  });

  test("redirect handoff is limited to trusted custom-scheme callback families", async () => {
    const hook = expo().hooks.after[0];
    expect(hook.matcher({ path: "/callback/google" })).toBe(true);
    expect(hook.matcher({ path: "/magic-link/verify-extra" })).toBe(true);
    expect(hook.matcher({ path: "/verify-email" })).toBe(true);
    expect(hook.matcher({ path: "/sign-in/email" })).toBe(false);

    const responseHeaders = new Headers({
      location: "oracle:///complete?existing=yes",
      "set-cookie": "better-auth.session_token=signed; HttpOnly; Path=/",
    });
    const handled = await hook.handler({ returnHeaders: true, context: {
      responseHeaders,
      isTrustedOrigin: (value) => value.startsWith("oracle://"),
    } });
    const location = new URL(handled.headers.get("location"));
    expect(location.searchParams.get("existing")).toBe("yes");
    expect(location.searchParams.get("cookie")).toBe(
      "better-auth.session_token=signed; HttpOnly; Path=/",
    );

    for (const target of [
      "https://web.example/complete",
      "evil:///complete",
      "oracle:///oauth-proxy-callback",
      "not a url",
    ]) {
      const headers = new Headers({ location: target, "set-cookie": "secret=value" });
      const ignored = await hook.handler({ returnHeaders: true, context: {
        responseHeaders: headers,
        isTrustedOrigin: (value) => value.startsWith("oracle://"),
      } });
      expect(headers.get("location")).toBe(target);
      expect(ignored.headers.get("location")).toBeNull();
    }
  });
});

describe("@better-auth/expo@1.7.1 native client interoperability", () => {
  test("pins cookie filtering, deletion, normalization, and chunk commits", async () => {
    expect(clientExports.normalizeCookieName("tenant:auth:cookie")).toBe("tenant_auth_cookie");
    expect(clientExports.hasBetterAuthCookies(
      "__Secure-better-auth.session_token=x; Path=/", "better-auth",
    )).toBe(true);
    expect(clientExports.hasBetterAuthCookies("third-party=x; Path=/", "better-auth")).toBe(false);

    const previous = JSON.stringify({
      "better-auth.session_token": { value: "old", expires: null },
      "better-auth.session_data": { value: "cached", expires: null },
    });
    expect(JSON.parse(clientExports.getSetCookie(
      "better-auth.session_token=; Max-Age=0", previous,
    ))).toEqual({
      "better-auth.session_data": { value: "cached", expires: null },
    });

    const storage = memoryStorage();
    const adapter = clientExports.storageAdapter(storage);
    const value = "x".repeat(3601);
    await adapter.setItemAsync("tenant:cookie", value);
    expect(storage.values.get("tenant_cookie")).toBe("\u0001ba-chunks:3");
    expect(storage.values.get("tenant_cookie.0")).toHaveLength(1800);
    expect(storage.values.get("tenant_cookie.1")).toHaveLength(1800);
    expect(storage.values.get("tenant_cookie.2")).toHaveLength(1);
    expect(await adapter.getItemAsync("tenant:cookie")).toBe(value);
    storage.values.delete("tenant_cookie.1");
    expect(await adapter.getItemAsync("tenant:cookie")).toBeNull();
  });

  test("native init sends exact transport headers and rewrites only exact callback keys", async () => {
    platform.OS = "android";
    const storage = memoryStorage();
    storage.values.set("better-auth_cookie", JSON.stringify({
      "better-auth.session_token": { value: "signed", expires: null },
    }));
    const plugin = clientExports.expoClient({ scheme: "oracle", storage });
    const init = plugin.fetchPlugins[0].init;
    const body = {
      callbackURL: "/done",
      newUserCallbackURL: "/new",
      errorCallbackURL: "/error",
      callbackUrl: "/wrong-case",
    };
    const result = await init("https://auth.example/api/auth/sign-in/social", { body });
    expect(result.options.credentials).toBe("omit");
    expect(result.options.headers).toMatchObject({
      cookie: "better-auth.session_token=signed",
      "expo-origin": "oracle://",
      "x-skip-oauth-proxy": "true",
    });
    expect(body).toEqual({
      callbackURL: "oracle:///done",
      newUserCallbackURL: "oracle:///new",
      errorCallbackURL: "oracle:///error",
      callbackUrl: "/wrong-case",
    });

    const idToken = await init("https://auth.example/api/auth/sign-in/social", {
      body: { idToken: { token: "provider-token" } },
    });
    expect(idToken.options.headers).toEqual({ "x-skip-oauth-proxy": "true" });
  });

  test("web init is an exact pass-through", async () => {
    platform.OS = "web";
    const plugin = clientExports.expoClient({ storage: memoryStorage() });
    const options = { credentials: "include", body: { callbackURL: "/browser" } };
    const result = await plugin.fetchPlugins[0].init("https://auth.example/sign-in", options);
    expect(result).toEqual({ url: "https://auth.example/sign-in", options });
  });

  test("lastLoginMethodClient remains client-only with its exact storage key", async () => {
    const storage = memoryStorage();
    const plugin = pluginExports.lastLoginMethodClient({ storage, storagePrefix: "oracle" });
    expect(plugin.id).toBe("last-login-method-expo");
    expect(plugin.version).toBe("1.7.1");
    expect(plugin).not.toHaveProperty("endpoints");
    await plugin.fetchPlugins[0].hooks.onResponse({
      request: { url: "https://auth.example/api/auth/sign-in/email" },
    });
    expect(storage.values.get("oracle_last_login_method")).toBe("email");
    const actions = plugin.getActions();
    expect(actions.getLastUsedLoginMethod()).toBe("email");
    expect(actions.isLastUsedLoginMethod("email")).toBe(true);
    await actions.clearLastUsedLoginMethod();
    expect(actions.getLastUsedLoginMethod()).toBeNull();
  });
});
