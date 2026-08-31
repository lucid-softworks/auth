import { creem } from "@creem_io/better-auth";
import * as creemRoot from "@creem_io/better-auth";
import { creemClient } from "@creem_io/better-auth/client";
import * as creemServer from "@creem_io/better-auth/server";
import { generateSignature } from "@creem_io/webhook-types";
import { betterAuth } from "better-auth";
import { createAuthClient } from "better-auth/client";
import { Creem } from "creem";
import { readFile } from "node:fs/promises";
import { afterEach, describe, expect, test, vi } from "vitest";

const authSecret = "zS7pFv9Kx3Qm2Wc8Rj6Hd4Nt1Uy5Ba0L";

const endpointMetadata = {
  createCheckout: ["/creem/create-checkout", "POST"],
  createPortal: ["/creem/create-portal", "POST"],
  cancelSubscription: ["/creem/cancel-subscription", "POST"],
  retrieveSubscription: ["/creem/retrieve-subscription", "POST"],
  searchTransactions: ["/creem/search-transactions", "POST"],
  hasAccessGranted: ["/creem/has-access-granted", "GET"],
};

async function packageVersion(name) {
  const packageJson = JSON.parse(await readFile(
    new URL(`node_modules/${name}/package.json`, import.meta.url),
  ));
  return packageJson.version;
}

async function invokeServer(plugin, path, { body, headers = {}, method = "POST" } = {}) {
  const auth = betterAuth({
    baseURL: "https://auth.example.test",
    plugins: [plugin],
    secret: authSecret,
  });
  const requestHeaders = new Headers(headers);
  let requestBody;
  if (body !== undefined) {
    requestHeaders.set("content-type", "application/json");
    requestBody = typeof body === "string" ? body : JSON.stringify(body);
  }
  return auth.handler(new Request(`https://auth.example.test/api/auth${path}`, {
    body: requestBody,
    headers: requestHeaders,
    method,
  }));
}

async function invokeDirect(endpoint, body) {
  return endpoint({
    asResponse: true,
    body,
    context: {
      logger: { debug() {}, error() {}, info() {}, warn() {} },
      session: null,
    },
    headers: new Headers(),
    request: new Request(`https://auth.example.test/api/auth${endpoint.path}`, {
      body: JSON.stringify(body),
      headers: { "content-type": "application/json" },
      method: "POST",
    }),
  });
}

function captureFetch(handler) {
  const requests = [];
  const fetch = vi.fn(async (input, init = {}) => {
    const request = input instanceof Request ? input : new Request(input, init);
    requests.push({
      body: request.body ? await request.clone().text() : null,
      headers: Object.fromEntries(request.headers),
      method: request.method,
      url: request.url,
    });
    return handler(request);
  });
  vi.stubGlobal("fetch", fetch);
  return { fetch, requests };
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("@creem_io/better-auth@1.1.4 executable oracle", () => {
  test("pins the complete effective dependency and export surface", async () => {
    expect(await packageVersion("@creem_io/better-auth")).toBe("1.1.4");
    expect(await packageVersion("creem")).toBe("1.6.0");
    expect(await packageVersion("@creem_io/webhook-types")).toBe("1.0.0");
    expect(await packageVersion("better-auth")).toBe("1.7.2");
    expect(await packageVersion("zod")).toBe("4.4.3");
    expect(Object.keys(creemRoot).sort()).toEqual([
      "cancelSubscription", "checkSubscriptionAccess", "createCheckout",
      "createCreemClient", "createPortal", "creem", "formatCreemDate",
      "getActiveSubscriptions", "getDaysUntilRenewal", "isActiveSubscription",
      "retrieveSubscription", "searchTransactions", "validateWebhookSignature",
    ]);
    expect(Object.keys(creemServer).sort()).toEqual([
      "cancelSubscription", "checkSubscriptionAccess", "createCheckout",
      "createCreemClient", "createPortal", "formatCreemDate",
      "getActiveSubscriptions", "getDaysUntilRenewal", "isActiveSubscription",
      "retrieveSubscription", "searchTransactions", "validateWebhookSignature",
    ]);
    expect(creemClient()).toMatchObject({
      id: "creem",
      pathMethods: {
        "/creem/cancel-subscription": "POST",
        "/creem/create-portal": "POST",
        "/creem/retrieve-subscription": "POST",
        "/creem/search-transactions": "POST",
      },
    });
  });

  test("plugin metadata, conditional schema, and schema merge failures are exact", () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const disabled = creem({ apiKey: "", persistSubscriptions: false });
    expect(disabled.id).toBe("creem");
    expect(Object.fromEntries(Object.entries(disabled.endpoints).map(([name, endpoint]) => [
      name,
      [endpoint.path, endpoint.options?.method],
    ]))).toEqual(endpointMetadata);
    expect(disabled.schema).toEqual({});
    expect(disabled.endpoints.webhook).toBeUndefined();

    const enabled = creem({ apiKey: "", webhookSecret: "secret" });
    expect(enabled.endpoints.creemWebhook.path).toBe("/creem/webhook");
    expect(enabled.schema.creem_subscription.fields).toMatchObject({
      cancelAtPeriodEnd: { defaultValue: false, required: false, type: "boolean" },
      productId: { required: true, type: "string" },
      referenceId: { required: true, type: "string" },
      status: { defaultValue: "pending", type: "string" },
    });
    expect(enabled.schema.user.fields).toEqual({
      creemCustomerId: { required: false, type: "string" },
      hadTrial: { defaultValue: false, required: false, type: "boolean" },
    });
    expect(() => creem({
      apiKey: "",
      persistSubscriptions: false,
      schema: { user: { fields: { creemCustomerId: "customer_id" } } },
    })).toThrow("Cannot read properties of undefined");
    expect(() => creem({ apiKey: "", schema: { unknown: { fields: {} } } }))
      .toThrow("Cannot read properties of undefined");

    const ignored = creem({
      apiKey: "",
      schema: { user: { fields: { unknown: "ignored", creemCustomerId: "" }, modelName: "" } },
    });
    expect(ignored.schema.user.fields.creemCustomerId.fieldName).toBeUndefined();
    expect(ignored.schema.user.modelName).toBeUndefined();
  });

  test("Better Call validation is HTTP 400 while every handler error is outer HTTP 200", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
    const invalid = await invokeServer(
      creem({ apiKey: "", persistSubscriptions: false }),
      "/creem/create-checkout",
      { body: {} },
    );
    expect(invalid.status).toBe(400);
    expect(await invalid.json()).toEqual({
      code: "VALIDATION_ERROR",
      message: "[body.productId] Invalid input: expected string, received undefined",
    });

    const handlerCases = [
      [creem({ apiKey: "", persistSubscriptions: false }), "/creem/create-checkout", "POST", { productId: "product" }, { error: "Creem API key is not configured. Please set the apiKey option when initializing the Creem plugin." }],
      [creem({ apiKey: "key", persistSubscriptions: false }), "/creem/create-portal", "POST", {}, { error: "User must be logged in" }],
      [creem({ apiKey: "", persistSubscriptions: false }), "/creem/has-access-granted", "GET", undefined, { message: "User must be logged in to check subscription status" }],
    ];
    for (const [plugin, path, method, body, expected] of handlerCases) {
      const response = await invokeServer(plugin, path, { body, method });
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual(expected);
    }

    const directMissingKey = await invokeDirect(
      creem({ apiKey: "", persistSubscriptions: false }).endpoints.createCheckout,
      { productId: "product" },
    );
    expect(directMissingKey.status).toBe(500);
    const directMissingSession = await invokeDirect(
      creem({ apiKey: "key", persistSubscriptions: false }).endpoints.createPortal,
      {},
    );
    expect(directMissingSession.status).toBe(400);
  });

  test("official client sends the exact six typed requests and treats outer-200 errors as data", async () => {
    const { requests } = captureFetch(() => Response.json({ ok: true }));
    const client = createAuthClient({
      baseURL: "https://auth.example.test",
      fetchOptions: { customFetchImpl: globalThis.fetch },
      plugins: [creemClient()],
    });
    await client.creem.createCheckout({ productId: "prod" });
    await client.creem.createPortal();
    await client.creem.cancelSubscription();
    await client.creem.retrieveSubscription();
    await client.creem.searchTransactions();
    await client.creem.hasAccessGranted();
    expect(requests.map(({ body, method, url }) => ({ body, method, url }))).toEqual([
      { body: '{"productId":"prod"}', method: "POST", url: "https://auth.example.test/api/auth/creem/create-checkout" },
      { body: "{}", method: "POST", url: "https://auth.example.test/api/auth/creem/create-portal" },
      { body: "{}", method: "POST", url: "https://auth.example.test/api/auth/creem/cancel-subscription" },
      { body: "{}", method: "POST", url: "https://auth.example.test/api/auth/creem/retrieve-subscription" },
      { body: "{}", method: "POST", url: "https://auth.example.test/api/auth/creem/search-transactions" },
      { body: null, method: "GET", url: "https://auth.example.test/api/auth/creem/has-access-granted" },
    ]);

    vi.stubGlobal("fetch", vi.fn(async () => Response.json({ error: "User must be logged in" })));
    const errorClient = createAuthClient({
      baseURL: "https://auth.example.test",
      fetchOptions: { customFetchImpl: globalThis.fetch },
      plugins: [creemClient()],
    });
    expect(await errorClient.creem.createPortal()).toEqual({
      data: { error: "User must be logged in" },
      error: null,
    });
  });

  test("generated SDK sends all five provider requests and normalizes response models", async () => {
    const subscription = {
      collection_method: "charge_automatically",
      created_at: "2026-07-01T00:00:00.000Z",
      current_period_end_date: "2026-09-01T00:00:00.000Z",
      current_period_start_date: "2026-08-01T00:00:00.000Z",
      customer: "customer_1",
      id: "subscription_1",
      mode: "test",
      object: "subscription",
      product: "product_1",
      status: "active",
      updated_at: "2026-08-01T00:00:00.000Z",
      unknown: "stripped",
    };
    const { requests } = captureFetch((request) => {
      const url = new URL(request.url);
      if (url.pathname.endsWith("/checkouts")) return Response.json({
        checkout_url: "https://checkout.test/1", id: "checkout_1", mode: "test",
        object: "checkout", product: "product_1", status: "pending", unknown: true,
      });
      if (url.pathname.endsWith("/customers/billing")) {
        return Response.json({ customer_portal_link: "https://portal.test/1", unknown: true });
      }
      if (url.pathname.endsWith("/transactions/search")) return Response.json({
        items: [], pagination: { current_page: 1, next_page: null, prev_page: null, total_pages: 1, total_records: 0 }, unknown: true,
      });
      return Response.json(subscription);
    });
    const client = new Creem({ apiKey: "secret_key", serverURL: "https://provider.test/base" });
    const checkout = await client.checkouts.create({
      customer: { email: "user@example.com" }, discountCode: "SAVE",
      metadata: { nested: { retained: true } }, productId: "product_1",
      requestId: "request 1", successUrl: "https://app.test/success", units: 1.5,
    });
    const portal = await client.customers.generateBillingLinks({ customerId: "customer_1" });
    const canceled = await client.subscriptions.cancel("a/b ?", {});
    const retrieved = await client.subscriptions.get("sub id&x");
    const searched = await client.transactions.search("customer 1", "order&1", "product/1");
    expect(requests.map(({ method, url }) => ({ method, url }))).toEqual([
      { method: "POST", url: "https://provider.test/base/v1/checkouts" },
      { method: "POST", url: "https://provider.test/base/v1/customers/billing" },
      { method: "POST", url: "https://provider.test/base/v1/subscriptions/a%2Fb%20%3F/cancel" },
      { method: "GET", url: "https://provider.test/base/v1/subscriptions?subscription_id=sub%20id%26x" },
      { method: "GET", url: "https://provider.test/base/v1/transactions/search?customer_id=customer%201&order_id=order%261&page_number=1&page_size=10&product_id=product%2F1" },
    ]);
    expect(requests.every(request => request.headers["x-api-key"] === "secret_key")).toBe(true);
    expect(requests[0].body).toBe('{"request_id":"request 1","product_id":"product_1","units":1.5,"discount_code":"SAVE","customer":{"email":"user@example.com"},"success_url":"https://app.test/success","metadata":{"nested":{"retained":true}}}');
    expect(checkout).toMatchObject({ checkoutUrl: "https://checkout.test/1" });
    expect(checkout.unknown).toBeUndefined();
    expect(portal).toEqual({ customerPortalLink: "https://portal.test/1" });
    expect(canceled.currentPeriodEndDate).toBeInstanceOf(Date);
    expect(retrieved.unknown).toBeUndefined();
    expect(JSON.parse(JSON.stringify(searched))).toEqual({
      result: { items: [], pagination: { currentPage: 1, nextPage: null, prevPage: null, totalPages: 1, totalRecords: 0 } },
    });
  });

  test("checkout route keeps truthiness, URL precedence, missing URL, and one-attempt errors", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    let mode = "missing-url";
    const { fetch, requests } = captureFetch(() => mode === "error"
      ? Response.json({ message: "provider detail" }, { status: 500 })
      : Response.json({ id: "checkout_1", mode: "test", object: "checkout", product: "product_1", status: "pending" }));
    const plugin = creem({ apiKey: "secret_key", persistSubscriptions: false, testMode: true });
    const missingUrl = await invokeServer(plugin, "/creem/create-checkout", {
      body: {
        customField: [{ key: "ignored", label: "Ignored", type: "text" }],
        customFields: [], customer: { email: "explicit@example.com" },
        metadata: { referenceId: "caller", skipTrial: false },
        productId: "product_1", successUrl: "/done",
      },
      headers: { host: "internal.test", "x-forwarded-host": "forwarded.test", "x-forwarded-proto": "http" },
    });
    expect(missingUrl.status).toBe(200);
    expect(await missingUrl.json()).toEqual({ redirect: true });
    expect(JSON.parse(requests[0].body)).toMatchObject({
      customer: { email: "explicit@example.com" }, custom_fields: [],
      metadata: { referenceId: "caller", skipTrial: false },
      success_url: "http://internal.test/done",
    });
    mode = "error";
    const before = fetch.mock.calls.length;
    const failed = await invokeServer(plugin, "/creem/create-checkout", { body: { productId: "product_1" } });
    expect(failed.status).toBe(200);
    expect(await failed.json()).toEqual({ error: "Failed to create checkout" });
    expect(fetch.mock.calls.length - before).toBe(1);
  });

  test("webhook verifies decoded text and preserves shallow callback collisions and failure order", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const calls = [];
    let failGrant = false;
    const webhookSecret = "webhook_secret";
    const plugin = creem({
      apiKey: "key",
      onGrantAccess: async value => {
        calls.push(["grant", value]);
        if (failGrant) throw new Error("callback failed");
      },
      onSubscriptionActive: async value => calls.push(["active", value]),
      persistSubscriptions: false,
      webhookSecret,
    });
    const send = async (id) => {
      const payload = JSON.stringify({
        created_at: 123, eventType: "subscription.active", id,
        object: {
          date: "not-normalized", extra: { retained: true }, object: "customer",
          reason: "object_reason", webhookCreatedAt: 456,
          webhookEventType: "object_type", webhookId: "object_id",
        },
      });
      return invokeServer(plugin, "/creem/webhook", {
        body: payload,
        headers: { "creem-signature": await generateSignature(payload, webhookSecret) },
      });
    };
    const success = await send("evt_1");
    expect(await success.json()).toEqual({ message: "Webhook received" });
    expect(calls).toEqual([
      ["grant", expect.objectContaining({ reason: "object_reason", webhookId: "object_id" })],
      ["active", expect.objectContaining({ date: "not-normalized", webhookEventType: "object_type" })],
    ]);
    failGrant = true;
    const failed = await send("evt_2");
    expect(failed.status).toBe(200);
    expect(await failed.json()).toEqual({ error: "Failed to process webhook" });
    expect(calls.filter(([name]) => name === "active")).toHaveLength(1);

    const invalid = await invokeServer(plugin, "/creem/webhook", {
      body: "{}", headers: { "creem-signature": "wrong" },
    });
    expect(invalid.status).toBe(200);
    expect(await invalid.json()).toEqual({ error: "Invalid signature" });
  });

  test("pure server helpers retain their exact runtime behavior", async () => {
    expect(creemServer.isActiveSubscription("ACTIVE")).toBe(true);
    expect(creemServer.isActiveSubscription("trialing")).toBe(true);
    expect(creemServer.isActiveSubscription("PAID")).toBe(true);
    expect(creemServer.isActiveSubscription("past_due")).toBe(false);
    expect(creemServer.formatCreemDate(1).toISOString()).toBe("1970-01-01T00:00:01.000Z");
    expect(creemServer.getDaysUntilRenewal((Date.now() / 1000) + 86_401)).toBe(2);
    const payload = '{"eventType":"subscription.active"}';
    const signature = await generateSignature(payload, "secret");
    expect(await creemServer.validateWebhookSignature(payload, signature, "secret")).toBe(true);
    expect(await creemServer.validateWebhookSignature(payload, null, "secret")).toBe(false);
  });
});
