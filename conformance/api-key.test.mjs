import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { describe, expect, test } from "vitest";
import { apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";

const origin = "https://api-key.example.test";
const baseURL = `${origin}/api/auth`;
const secret = "K".repeat(32);
const apiKeyPackage = JSON.parse(
  await readFile(
    new URL("node_modules/@better-auth/api-key/package.json", import.meta.url),
    "utf8",
  ),
);

function jsonRequest(body, headers = {}) {
  return {
    method: "POST",
    headers: { "content-type": "application/json", origin, ...headers },
    body: JSON.stringify(body),
  };
}

function request(auth, path, init = {}) {
  return auth.handler(new Request(`${baseURL}${path}`, init));
}

function apiKeyAuth(configuration, options = {}) {
  return betterAuth({
    baseURL,
    secret,
    emailAndPassword: { enabled: true },
    logger: { disabled: true },
    plugins: [apiKey(configuration)],
    ...options,
  });
}

function sessionCookie(response) {
  const cookie = response.headers
    .getSetCookie()
    .find((candidate) =>
      candidate.slice(0, candidate.indexOf("=")).endsWith(".session_token"),
    );
  expect(cookie).toBeDefined();
  return cookie.split(";", 1)[0];
}

async function signUp(auth, identity) {
  const response = await request(
    auth,
    "/sign-up/email",
    jsonRequest({
      name: `API Key ${identity}`,
      email: `${identity}@example.com`,
      password: "correct horse battery staple",
    }),
  );
  expect(response.status).toBe(200);
  return {
    body: await response.clone().json(),
    cookie: sessionCookie(response),
  };
}

class RecordingSecondaryStorage {
  constructor() {
    this.values = new Map();
    this.calls = [];
  }

  async get(key) {
    this.calls.push(["get", key]);
    return this.values.get(key) ?? null;
  }

  async getAndDelete(key) {
    this.calls.push(["getAndDelete", key]);
    const value = this.values.get(key) ?? null;
    this.values.delete(key);
    return value;
  }

  async increment(key, amount) {
    this.calls.push(["increment", key, amount]);
    const next = Number(this.values.get(key) ?? 0) + amount;
    this.values.set(key, String(next));
    return next;
  }

  async set(key, value, ttl) {
    this.calls.push(["set", key, value, ttl]);
    this.values.set(key, value);
  }

  async delete(key) {
    this.calls.push(["delete", key]);
    this.values.delete(key);
  }
}

describe("@better-auth/api-key 1.7.2 oracle", () => {
  test("pins package, plugin metadata, schema, and multi-configuration errors", () => {
    expect(apiKeyPackage.version).toBe("1.7.2");
    const plugin = apiKey();
    expect(plugin.id).toBe("api-key");
    expect(plugin.version).toBe("1.7.2");
    expect(Object.keys(plugin.endpoints)).toEqual([
      "createApiKey",
      "verifyApiKey",
      "getApiKey",
      "updateApiKey",
      "deleteApiKey",
      "listApiKeys",
      "deleteAllExpiredApiKeys",
    ]);
    expect(Object.keys(plugin.schema)).toEqual(["apikey"]);
    expect(Object.keys(plugin.schema.apikey.fields)).toEqual([
      "configId",
      "name",
      "start",
      "referenceId",
      "prefix",
      "key",
      "refillInterval",
      "refillAmount",
      "lastRefillAt",
      "enabled",
      "rateLimitEnabled",
      "rateLimitTimeWindow",
      "rateLimitMax",
      "requestCount",
      "remaining",
      "lastRequest",
      "expiresAt",
      "createdAt",
      "updatedAt",
      "permissions",
      "metadata",
    ]);
    expect(plugin.schema.apikey.fields.configId).toMatchObject({
      defaultValue: "default",
      index: true,
      required: true,
      type: "string",
    });

    expect(() => apiKey([{ configId: "default" }, {}])).toThrow(
      "configId is required for each API key configuration in the api-key plugin.",
    );
    expect(() =>
      apiKey([{ configId: "duplicate" }, { configId: "duplicate" }]),
    ).toThrow(
      "configId must be unique for each API key configuration in the api-key plugin.",
    );
    expect(() => apiKey([])).not.toThrow();
  });

  test("pins secondary-only ID fallback, generation, hashing, keys, and serialization", async () => {
    const storage = new RecordingSecondaryStorage();
    const generatorCalls = [];
    const plugin = apiKey({
      storage: "secondary-storage",
      customStorage: storage,
      defaultKeyLength: 11,
      defaultPrefix: "default_",
      startingCharactersConfig: { shouldStore: true, charactersLength: 9 },
      customKeyGenerator: async (input) => {
        generatorCalls.push(input);
        return `${input.prefix ?? ""}VisibleSecret`;
      },
    });
    const auth = betterAuth({
      baseURL,
      secret,
      emailAndPassword: { enabled: true },
      logger: { disabled: true },
      plugins: [plugin],
    });
    const signedUp = await signUp(auth, "secondary-only");
    const response = await request(
      auth,
      "/api-key/create",
      jsonRequest({ name: "oracle", prefix: "request_" }, { cookie: signedUp.cookie }),
    );
    expect(response.status).toBe(200);
    const created = await response.json();
    expect(generatorCalls).toEqual([{ length: 11, prefix: "request_" }]);
    expect(created).toMatchObject({
      configId: "default",
      key: "request_VisibleSecret",
      prefix: "request_",
      start: "request_V",
      referenceId: signedUp.body.user.id,
    });
    expect(created.id).toMatch(/^[A-Za-z0-9]{32}$/);

    const hashed = createHash("sha256")
      .update(created.key)
      .digest("base64url");
    const serialized = JSON.parse(storage.values.get(`api-key:${hashed}`));
    expect(serialized).toMatchObject({
      id: created.id,
      configId: "default",
      key: hashed,
      referenceId: signedUp.body.user.id,
      prefix: "request_",
      start: "request_V",
    });
    expect(serialized).not.toHaveProperty("key", created.key);
    expect(storage.values.get(`api-key:by-id:${created.id}`)).toBe(
      storage.values.get(`api-key:${hashed}`),
    );
    expect(
      JSON.parse(storage.values.get(`api-key:by-ref:${signedUp.body.user.id}`)),
    ).toEqual([created.id]);
    expect(serialized.expiresAt).toBeNull();
    expect(serialized.lastRefillAt).toBeNull();
    expect(serialized.lastRequest).toBeNull();
    expect(new Date(serialized.createdAt).toISOString()).toBe(serialized.createdAt);
    expect(new Date(serialized.updatedAt).toISOString()).toBe(serialized.updatedAt);
    expect(storage.calls.some(([method]) => method === "increment")).toBe(false);
  });

  test("pins unknown config fallback and null/default record matching", async () => {
    const auth = betterAuth({
      baseURL,
      secret,
      emailAndPassword: { enabled: true },
      logger: { disabled: true },
      plugins: [
        apiKey([
          { configId: "default", defaultPrefix: "default_" },
          { configId: "other", defaultPrefix: "other_" },
        ]),
      ],
    });
    const signedUp = await signUp(auth, "configuration-fallback");
    const response = await request(
      auth,
      "/api-key/create",
      jsonRequest(
        { configId: "missing", name: "fallback" },
        { cookie: signedUp.cookie },
      ),
    );
    expect(response.status).toBe(200);
    const created = await response.json();
    expect(created.configId).toBe("default");
    expect(created.prefix).toBe("default_");
    expect(created.key.startsWith("default_")).toBe(true);
  });

  test("pins request getter calls, validation order, and error responses", async () => {
    const events = [];
    const storage = new RecordingSecondaryStorage();
    const storageGet = storage.get.bind(storage);
    storage.get = async (key) => {
      events.push(["storage", key]);
      return storageGet(key);
    };
    let requestKey = null;
    let validatorResult = true;
    const auth = apiKeyAuth({
      storage: "secondary-storage",
      customStorage: storage,
      defaultKeyLength: 12,
      enableSessionForAPIKeys: true,
      customKeyGenerator: () => "OracleSessionKey",
      customAPIKeyGetter: (ctx) => {
        events.push(["getter", ctx.path]);
        return requestKey;
      },
      customAPIKeyValidator: ({ ctx, key }) => {
        events.push(["validator", ctx.path, key]);
        return validatorResult;
      },
    });
    const signedUp = await signUp(auth, "request-hooks");
    const createResponse = await request(
      auth,
      "/api-key/create",
      jsonRequest({ name: "hooks" }, { cookie: signedUp.cookie }),
    );
    expect(createResponse.status).toBe(200);
    const created = await createResponse.json();

    events.length = 0;
    storage.calls.length = 0;
    requestKey = created.key;
    const sessionResponse = await request(auth, "/get-session");
    expect(sessionResponse.status).toBe(200);
    expect(events.slice(0, 4)).toEqual([
      ["getter", "/get-session"],
      ["getter", "/get-session"],
      ["validator", "/get-session", created.key],
      ["storage", `api-key:${createHash("sha256").update(created.key).digest("base64url")}`],
    ]);
    expect(events.filter(([kind]) => kind === "getter")).toHaveLength(2);
    expect(events.filter(([kind]) => kind === "validator")).toHaveLength(1);

    events.length = 0;
    storage.calls.length = 0;
    validatorResult = false;
    const rejected = await request(auth, "/get-session");
    expect(rejected.status).toBe(403);
    expect(await rejected.json()).toEqual({
      code: "INVALID_API_KEY",
      message: "Invalid API key.",
    });
    expect(events).toEqual([
      ["getter", "/get-session"],
      ["getter", "/get-session"],
      ["validator", "/get-session", created.key],
    ]);
    expect(storage.calls).toEqual([]);

    const badGetterCalls = [];
    const invalidGetterAuth = apiKeyAuth({
      defaultKeyLength: 1,
      enableSessionForAPIKeys: true,
      customAPIKeyGetter: (ctx) => {
        badGetterCalls.push(ctx.path);
        return 42;
      },
    });
    const invalidGetter = await request(invalidGetterAuth, "/get-session");
    expect(invalidGetter.status).toBe(400);
    expect(await invalidGetter.json()).toEqual({
      code: "INVALID_API_KEY_GETTER_RETURN_TYPE",
      message: "API Key getter returned an invalid key type. Expected string.",
    });
    expect(badGetterCalls).toEqual(["/get-session", "/get-session"]);

    const verificationEvents = [];
    const verificationStorage = new RecordingSecondaryStorage();
    verificationStorage.values = storage.values;
    const verificationGet = verificationStorage.get.bind(verificationStorage);
    verificationStorage.get = async (key) => {
      verificationEvents.push(["storage", key]);
      return verificationGet(key);
    };
    const verificationAuth = apiKeyAuth({
      storage: "secondary-storage",
      customStorage: verificationStorage,
      defaultKeyLength: 12,
      customAPIKeyValidator: ({ ctx, key }) => {
        verificationEvents.push(["validator", ctx.path, key]);
        return true;
      },
    });
    const explicitConfig = await verificationAuth.api.verifyApiKey({
      body: { configId: "default", key: created.key },
    });
    expect(explicitConfig.valid).toBe(true);
    expect(verificationEvents.slice(0, 2).map(([kind]) => kind)).toEqual([
      "validator",
      "storage",
    ]);

    verificationEvents.length = 0;
    const inferredConfig = await verificationAuth.api.verifyApiKey({
      body: { key: created.key },
    });
    expect(inferredConfig.valid).toBe(true);
    expect(verificationEvents.slice(0, 2).map(([kind]) => kind)).toEqual([
      "storage",
      "validator",
    ]);
  });

  test("pins ordered headers and the default x-api-key header", async () => {
    const storage = new RecordingSecondaryStorage();
    const auth = apiKeyAuth({
      storage: "secondary-storage",
      customStorage: storage,
      defaultKeyLength: 12,
      enableSessionForAPIKeys: true,
      apiKeyHeaders: ["x-first-key", "x-second-key"],
      customKeyGenerator: () => "OrderedHeaderKey",
    });
    const signedUp = await signUp(auth, "ordered-headers");
    const createResponse = await request(
      auth,
      "/api-key/create",
      jsonRequest({ name: "headers" }, { cookie: signedUp.cookie }),
    );
    const created = await createResponse.json();

    const firstWins = await request(auth, "/get-session", {
      headers: {
        "x-first-key": "DefinitelyInvalid",
        "x-second-key": created.key,
      },
    });
    expect(firstWins.status).toBe(401);
    expect(await firstWins.json()).toEqual({
      code: "INVALID_API_KEY",
      message: "Invalid API key.",
    });

    const skipsEmpty = await request(auth, "/get-session", {
      headers: { "x-first-key": "", "x-second-key": created.key },
    });
    expect(skipsEmpty.status).toBe(200);

    const defaultStorage = new RecordingSecondaryStorage();
    const defaultHeaderAuth = apiKeyAuth({
      storage: "secondary-storage",
      customStorage: defaultStorage,
      defaultKeyLength: 12,
      enableSessionForAPIKeys: true,
      customKeyGenerator: () => "DefaultHeaderKey",
    });
    const defaultSignedUp = await signUp(defaultHeaderAuth, "default-header");
    const defaultCreate = await request(
      defaultHeaderAuth,
      "/api-key/create",
      jsonRequest({ name: "default" }, { cookie: defaultSignedUp.cookie }),
    );
    const defaultCreated = await defaultCreate.json();
    const defaultSession = await request(defaultHeaderAuth, "/get-session", {
      headers: { "x-api-key": defaultCreated.key },
    });
    expect(defaultSession.status).toBe(200);
  });

  test("pins plaintext storage, expiry TTLs, and synthesized sessions", async () => {
    const storage = new RecordingSecondaryStorage();
    const auth = apiKeyAuth(
      {
        storage: "secondary-storage",
        customStorage: storage,
        defaultKeyLength: 12,
        disableKeyHashing: true,
        enableSessionForAPIKeys: true,
        rateLimit: { enabled: false },
        customKeyGenerator: () => "PlaintextOracleKey",
      },
      { session: { expiresIn: 12345 } },
    );
    const signedUp = await signUp(auth, "plaintext-session");
    storage.calls.length = 0;
    const createResponse = await request(
      auth,
      "/api-key/create",
      jsonRequest(
        { name: "plaintext", expiresIn: 86400 },
        { cookie: signedUp.cookie },
      ),
    );
    expect(createResponse.status).toBe(200);
    const created = await createResponse.json();
    expect(created.key).toBe("PlaintextOracleKey");
    expect(storage.values.has(`api-key:${created.key}`)).toBe(true);
    expect(
      storage.values.has(
        `api-key:${createHash("sha256").update(created.key).digest("base64url")}`,
      ),
    ).toBe(false);

    const serializedText = storage.values.get(`api-key:${created.key}`);
    const serialized = JSON.parse(serializedText);
    expect(serialized.key).toBe(created.key);
    expect(serialized.expiresAt).toBe(created.expiresAt);
    expect(new Date(serialized.expiresAt).toISOString()).toBe(
      serialized.expiresAt,
    );
    const recordWrites = storage.calls.filter(
      ([method, key]) =>
        method === "set" &&
        (key === `api-key:${created.key}` ||
          key === `api-key:by-id:${created.id}`),
    );
    expect(recordWrites).toHaveLength(2);
    expect(recordWrites.map(([, , value]) => value)).toEqual([
      serializedText,
      serializedText,
    ]);
    for (const [, , , ttl] of recordWrites) {
      expect(Number.isInteger(ttl)).toBe(true);
      expect(ttl).toBeGreaterThanOrEqual(86398);
      expect(ttl).toBeLessThanOrEqual(86400);
    }
    expect(
      storage.calls.find(
        ([method, key]) =>
          method === "set" &&
          key === `api-key:by-ref:${signedUp.body.user.id}`,
      ),
    ).toEqual([
      "set",
      `api-key:by-ref:${signedUp.body.user.id}`,
      JSON.stringify([created.id]),
      undefined,
    ]);

    const sessionResponse = await request(auth, "/get-session", {
      headers: {
        "user-agent": "api-key-oracle/1.0",
        "x-api-key": created.key,
      },
    });
    expect(sessionResponse.status).toBe(200);
    const mocked = await sessionResponse.json();
    expect(mocked.user).toMatchObject({
      id: signedUp.body.user.id,
      email: signedUp.body.user.email,
      name: signedUp.body.user.name,
    });
    expect(mocked.session).toMatchObject({
      id: created.id,
      token: created.key,
      userId: signedUp.body.user.id,
      userAgent: "api-key-oracle/1.0",
      ipAddress: "127.0.0.1",
      expiresAt: created.expiresAt,
    });
    expect(new Date(mocked.session.createdAt).getTime()).not.toBeNaN();
    expect(new Date(mocked.session.updatedAt).getTime()).not.toBeNaN();

    const fallbackStorage = new RecordingSecondaryStorage();
    const fallbackAuth = apiKeyAuth(
      {
        storage: "secondary-storage",
        customStorage: fallbackStorage,
        defaultKeyLength: 12,
        enableSessionForAPIKeys: true,
        rateLimit: { enabled: false },
        customKeyGenerator: () => "FallbackExpiryKey",
      },
      { session: { expiresIn: 12345 } },
    );
    const fallbackSignedUp = await signUp(fallbackAuth, "fallback-expiry");
    const fallbackCreate = await request(
      fallbackAuth,
      "/api-key/create",
      jsonRequest({ name: "fallback" }, { cookie: fallbackSignedUp.cookie }),
    );
    const fallbackCreated = await fallbackCreate.json();
    expect(fallbackCreated.expiresAt).toBeNull();
    const beforeSession = Date.now();
    const fallbackSessionResponse = await request(fallbackAuth, "/get-session", {
      headers: { "x-api-key": fallbackCreated.key },
    });
    const afterSession = Date.now();
    const fallbackSession = await fallbackSessionResponse.json();
    const fallbackExpiresAt = new Date(
      fallbackSession.session.expiresAt,
    ).getTime();
    expect(fallbackExpiresAt).toBeGreaterThanOrEqual(beforeSession + 12345);
    expect(fallbackExpiresAt).toBeLessThanOrEqual(afterSession + 12345);
  });

  test("pins user-only session mocking and configuration defaults", async () => {
    const storage = new RecordingSecondaryStorage();
    const userAuth = apiKeyAuth({
      storage: "secondary-storage",
      customStorage: storage,
      defaultKeyLength: 12,
      enableSessionForAPIKeys: true,
      customKeyGenerator: () => "ReferenceTypeKey",
    });
    const signedUp = await signUp(userAuth, "reference-type");
    const createResponse = await request(
      userAuth,
      "/api-key/create",
      jsonRequest({ name: "reference" }, { cookie: signedUp.cookie }),
    );
    const created = await createResponse.json();
    const organizationAuth = apiKeyAuth({
      storage: "secondary-storage",
      customStorage: storage,
      defaultKeyLength: 12,
      enableSessionForAPIKeys: true,
      references: "organization",
    });
    const organizationSession = await request(organizationAuth, "/get-session", {
      headers: { "x-api-key": created.key },
    });
    expect(organizationSession.status).toBe(401);
    expect(await organizationSession.json()).toEqual({
      code: "INVALID_REFERENCE_ID_FROM_API_KEY",
      message: "The reference id from the API key is invalid.",
    });

    const defaultsAuth = apiKeyAuth({});
    const defaultsSignUp = await signUp(defaultsAuth, "configuration-defaults");
    const defaultsResponse = await request(
      defaultsAuth,
      "/api-key/create",
      jsonRequest({}, { cookie: defaultsSignUp.cookie }),
    );
    expect(defaultsResponse.status).toBe(200);
    const defaults = await defaultsResponse.json();
    expect(defaults).toMatchObject({
      configId: "default",
      name: null,
      prefix: null,
      remaining: null,
      rateLimitEnabled: true,
      rateLimitMax: 10,
      rateLimitTimeWindow: 86400000,
      requestCount: 0,
      start: defaults.key.slice(0, 6),
    });
    expect(defaults.key).toMatch(/^[A-Za-z]+$/);
    expect(defaults.key).toHaveLength(64);

    const noDefaultAuth = apiKeyAuth([
      { configId: "first" },
      { configId: "second" },
    ]);
    const noDefaultSignUp = await signUp(noDefaultAuth, "no-default-config");
    const noDefaultResponse = await request(
      noDefaultAuth,
      "/api-key/create",
      jsonRequest({}, { cookie: noDefaultSignUp.cookie }),
    );
    expect(noDefaultResponse.status).toBe(400);
    expect(await noDefaultResponse.json()).toEqual({
      code: "NO_DEFAULT_API_KEY_CONFIGURATION_FOUND",
      message: "No default api-key configuration found.",
    });
  });
});
