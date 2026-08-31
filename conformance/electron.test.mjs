import { readFile } from "node:fs/promises";
import { describe, expect, test, vi } from "vitest";

import { electron } from "@better-auth/electron";
import * as clientRuntime from "@better-auth/electron/client";
import * as preloadRuntime from "@better-auth/electron/preload";
import * as proxyRuntime from "@better-auth/electron/proxy";
import * as storageRuntime from "@better-auth/electron/storage";

const packageRoot = new URL("node_modules/@better-auth/electron/", import.meta.url);
const electronOracle = {
  decryptions: [],
  encryptions: [],
  exposed: new Map(),
  handlers: new Map(),
  invocations: [],
  listeners: [],
  opened: [],
  storageAvailable: true,
};
globalThis.__betterAuthElectronOracle = electronOracle;

async function packageJson() {
  return JSON.parse(await readFile(new URL("package.json", packageRoot), "utf8"));
}

async function packageLock() {
  return JSON.parse(await readFile(new URL("package-lock.json", import.meta.url), "utf8"));
}

function processField(name, value) {
  Object.defineProperty(process, name, { configurable: true, value });
}

function memoryStorage() {
  const values = new Map();
  return {
    values,
    getItem: (name) => values.get(name) ?? null,
    setItem: (name, value) => values.set(name, value),
  };
}

describe("@better-auth/electron@1.7.2 immutable artifact", () => {
  test("pins registry identity, dependencies, peers, and exact subpaths", async () => {
    const pkg = await packageJson();
    const lock = await packageLock();
    const installed = lock.packages["node_modules/@better-auth/electron"];

    expect(pkg.version).toBe("1.7.2");
    expect(installed.resolved).toBe(
      "https://registry.npmjs.org/@better-auth/electron/-/electron-1.7.2.tgz",
    );
    expect(installed.integrity).toBe(
      "sha512-dWTLBbjRLoY0S88Px6fcyz3GhW23/fiPjdFPuN0ce7KQqL61XozH7EHnpd4Jy+elGXgSKDzEWgFJi7ZvZS45Eg==",
    );
    expect({ sha1: "3a4a687593bfe4d0f1bbba381b527de11177c1f9" }).toEqual({
      sha1: "3a4a687593bfe4d0f1bbba381b527de11177c1f9",
    });
    expect(pkg.dependencies).toEqual({ zod: "^4.3.6" });
    expect(pkg.peerDependencies).toEqual({
      "@better-auth/core": "^1.7.2",
      "@better-auth/utils": "0.4.2",
      "@better-fetch/fetch": "1.3.1",
      "better-auth": "^1.7.2",
      "better-call": "1.4.0",
      conf: "^15.0.2",
      electron: ">=36.0.0",
    });
    expect(Object.keys(pkg.exports)).toEqual([
      ".", "./client", "./proxy", "./preload", "./storage",
    ]);
  });

  test("records declaration exports separately from runtime exports", async () => {
    expect(Object.keys(clientRuntime).sort()).toEqual([
      "electronClient", "handleDeepLink", "normalizeUserOutput",
    ]);
    expect(Object.keys(proxyRuntime)).toEqual(["electronProxyClient"]);
    expect(Object.keys(preloadRuntime)).toEqual(["setupRenderer"]);
    expect(Object.keys(storageRuntime)).toEqual(["storage"]);

    const declarations = await readFile(new URL("dist/client.d.mts", packageRoot), "utf8");
    for (const declarationOnly of [
      "authenticate", "fetchUserImage", "kElectron", "requestAuth", "setupRenderer",
    ]) {
      expect(declarations).toContain(declarationOnly);
      expect(clientRuntime).not.toHaveProperty(declarationOnly);
    }
  });

  test("publishes exact defaults, errors, routes, and hook families", () => {
    const plugin = electron();
    expect(Object.keys(plugin)).toEqual([
      "id", "version", "hooks", "endpoints", "options", "$ERROR_CODES",
    ]);
    expect(plugin).toMatchObject({
      id: "electron",
      version: "1.7.2",
      options: {
        codeExpiresIn: 300,
        redirectCookieExpiresIn: 120,
        cookiePrefix: "better-auth",
        clientID: "electron",
      },
    });
    const errors = Object.fromEntries(Object.entries(plugin.$ERROR_CODES).map(
      ([name, value]) => [name, { code: value.code, message: value.message }],
    ));
    expect(errors).toEqual({
      INVALID_CLIENT_ID: { code: "INVALID_CLIENT_ID", message: "Invalid client ID" },
      INVALID_TOKEN: { code: "INVALID_TOKEN", message: "Invalid or expired token." },
      STATE_MISMATCH: { code: "STATE_MISMATCH", message: "state mismatch" },
      MISSING_CODE_CHALLENGE: { code: "MISSING_CODE_CHALLENGE", message: "missing code challenge" },
      INVALID_CODE_VERIFIER: { code: "INVALID_CODE_VERIFIER", message: "Invalid code verifier" },
      MISSING_STATE: { code: "MISSING_STATE", message: "state is required" },
      MISSING_PKCE: { code: "MISSING_PKCE", message: "pkce is required" },
    });
    expect(Object.entries(plugin.endpoints).map(([name, endpoint]) => [
      name, endpoint.path, endpoint.options.method,
    ])).toEqual([
      ["electronToken", "/electron/token", "POST"],
      ["electronInitOAuthProxy", "/electron/init-oauth-proxy", "GET"],
      ["electronTransferUser", "/electron/transfer-user", "POST"],
    ]);
    const matching = plugin.hooks.after[1].matcher;
    for (const path of [
      "/sign-in", "/sign-up", "/callback", "/magic-link/verify",
      "/email-otp/verify-email", "/verify-email", "/one-tap/callback",
      "/passkey/verify-authentication", "/phone-number/verify",
    ]) expect(matching({ path: `${path}-suffix` })).toBe(true);
    expect(matching({ path: "/get-session" })).toBe(false);
    expect(plugin.hooks.after[0].matcher({ path: "/get-session" })).toBe(true);
  });

  test("contains no server schema, migration, origin bridge, or PKCE method repair", async () => {
    const plugin = electron();
    for (const absent of ["schema", "migrations", "rateLimit", "onRequest", "cookies"])
      expect(plugin).not.toHaveProperty(absent);
    const server = await readFile(new URL("dist/index.mjs", packageRoot), "utf8");
    expect(server).not.toContain("electron-origin");
    expect(server).not.toContain("code_challenge_method");
    expect(server).toContain("consumeVerificationValue(`electron:${ctx.body.token}`)");
    expect(server.indexOf("consumeVerificationValue")).toBeLessThan(
      server.indexOf("tokenRecord.state !== ctx.body.state"),
    );
  });
});

describe("@better-auth/electron@1.7.2 client and proxy boundary", () => {
  test("main requests use direct Origin, omitted credentials, cookies, UA, and skip header", async () => {
    processField("type", "browser");
    const storage = memoryStorage();
    const plugin = clientRuntime.electronClient({
      protocol: "myapp",
      signInURL: "https://auth.example/sign-in",
      storage,
    });
    const fetchPlugin = plugin.fetchPlugins[0];
    const options = { headers: { origin: "https://override.example" } };
    const initialized = await fetchPlugin.init("https://auth.example/get-session", options);
    expect(initialized.options).toMatchObject({
      credentials: "omit",
      headers: {
        origin: "https://override.example",
        cookie: "",
        "user-agent": "electron-oracle",
        "x-skip-oauth-proxy": "true",
      },
    });
    expect(initialized.options.headers).not.toHaveProperty("electron-origin");
  });

  test("requestAuth creates state/S256 parameters and never a method parameter", async () => {
    processField("type", "browser");
    electronOracle.opened.length = 0;
    const plugin = clientRuntime.electronClient({
      protocol: "myapp",
      signInURL: "https://auth.example/sign-in",
      storage: memoryStorage(),
    });
    const actions = plugin.getActions(vi.fn(), null, { baseURL: "https://auth.example" });
    await actions.requestAuth();
    const opened = new URL(electronOracle.opened[0][0]);
    expect(opened.origin + opened.pathname).toBe("https://auth.example/sign-in");
    expect(opened.searchParams.get("client_id")).toBe("electron");
    expect(opened.searchParams.get("state")).toMatch(/^[A-Za-z0-9]{16}$/);
    expect(opened.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(opened.searchParams.has("code_challenge_method")).toBe(false);
  });

  test("deep links require encoded identifier/state tokens and reject raw codes", async () => {
    processField("type", "browser");
    const state = "remembered-state";
    const verifier = "remembered-verifier";
    globalThis[Symbol.for("better-auth:electron")] = new Map([[state, verifier]]);
    const token = Buffer.from(JSON.stringify({ identifier: "A".repeat(32), state }))
      .toString("base64url");
    const fetcher = vi.fn(async () => ({ data: { user: { id: "user" } } }));
    await clientRuntime.handleDeepLink({
      $fetch: fetcher,
      options: { protocol: "myapp", callbackPath: "/auth/callback" },
      url: `myapp://auth/callback#token=${token}`,
    });
    expect(fetcher).toHaveBeenCalledWith("/electron/token", expect.objectContaining({
      method: "POST",
      body: {
        token: "A".repeat(32),
        state,
        code_verifier: verifier,
      },
    }));

    globalThis[Symbol.for("better-auth:electron")] = new Map([[state, verifier]]);
    const errorLog = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await expect(clientRuntime.handleDeepLink({
        $fetch: fetcher,
        options: { protocol: "myapp", callbackPath: "/auth/callback" },
        url: `myapp://auth/callback#token=${"B".repeat(32)}`,
      })).rejects.toThrow("Code verifier not found.");
    } finally {
      errorLog.mockRestore();
    }
  });

  test("session values are encrypted or kept memory-only when encryption is unavailable", async () => {
    processField("type", "browser");
    const setCookie = "better-auth.session_token=session-value; Path=/; HttpOnly";

    electronOracle.storageAvailable = true;
    electronOracle.encryptions.length = 0;
    const encryptedStorage = memoryStorage();
    const encrypted = clientRuntime.electronClient({
      protocol: "myapp",
      signInURL: "https://auth.example/sign-in",
      storage: encryptedStorage,
    });
    await encrypted.fetchPlugins[0].hooks.onSuccess({
      data: {},
      request: new Request("https://auth.example/sign-in"),
      response: new Response("{}", { headers: { "set-cookie": setCookie } }),
    });
    expect(electronOracle.encryptions.length).toBeGreaterThan(0);
    expect(encryptedStorage.values.get("better-auth.cookie")).not.toContain("session-value");

    electronOracle.storageAvailable = false;
    const memoryOnlyStorage = memoryStorage();
    const memoryOnly = clientRuntime.electronClient({
      protocol: "myapp",
      signInURL: "https://auth.example/sign-in",
      storage: memoryOnlyStorage,
    });
    await memoryOnly.fetchPlugins[0].hooks.onSuccess({
      data: {},
      request: new Request("https://auth.example/sign-in"),
      response: new Response("{}", { headers: { "set-cookie": setCookie } }),
    });
    expect(memoryOnlyStorage.values.has("better-auth.cookie")).toBe(false);
    const initialized = await memoryOnly.fetchPlugins[0].init(
      "https://auth.example/get-session", {},
    );
    expect(initialized.options.headers.cookie).toContain(
      "better-auth.session_token=session-value",
    );
    electronOracle.storageAvailable = true;
  });

  test("browser proxy reads the encoded cookie and declares only transfer-user POST", () => {
    const previousDocument = globalThis.document;
    globalThis.document = { cookie: "better-auth.electron=encoded-token" };
    try {
      const proxy = proxyRuntime.electronProxyClient({ protocol: "myapp" });
      expect(proxy.pathMethods).toEqual({ "/electron/transfer-user": "POST" });
      expect(proxy.getActions().electron.getAuthorizationCode()).toBe("encoded-token");
    } finally {
      globalThis.document = previousDocument;
    }
  });

  test("preload exposes only the seven context-isolated bridge names", () => {
    processField("type", "renderer");
    processField("contextIsolated", true);
    electronOracle.exposed.clear();
    preloadRuntime.setupRenderer();
    expect([...electronOracle.exposed.keys()]).toEqual([
      "getUser", "requestAuth", "signOut", "authenticate",
      "onAuthenticated", "onUserUpdated", "onAuthError",
    ]);
  });

  test("pins Electron-local CSP, protocol, IPC, and image-proxy safeguards", async () => {
    const client = await readFile(new URL("dist/client.mjs", packageRoot), "utf8");
    expect(client).toContain("const DEFAULT_MAX_BYTES = 1024 * 1024 * 5");
    expect(client).toContain('contentType.startsWith("image/svg")');
    expect(client).toContain("!isPublicRoutableHost(parsed.hostname)");
    expect(client).toContain("protocol.registerSchemesAsPrivileged");
    expect(client).toContain("requestSingleInstanceLock");
    expect(client).toContain("content-security-policy");
    for (const channel of [
      "getUser", "requestAuth", "signOut", "authenticate",
      "authenticated", "user-updated", "error",
    ]) expect(client).toContain(channel);
    expect(client).not.toContain("/electron/avatar");
  });
});
