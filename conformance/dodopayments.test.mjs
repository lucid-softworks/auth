import {
  checkout,
  dodopayments,
  dodopaymentsClient,
  portal,
  usage,
  webhooks,
} from "@dodopayments/better-auth";
import * as dodoClientExports from "@dodopayments/better-auth/client";
import * as dodoRootExports from "@dodopayments/better-auth";
import { betterAuth } from "better-auth";
import { createAuthClient } from "better-auth/client";
import { createHmac } from "node:crypto";
import { readFile } from "node:fs/promises";
import { afterEach, describe, expect, test, vi } from "vitest";

const authSecret = "zS7pFv9Kx3Qm2Wc8Rj6Hd4Nt1Uy5Ba0L";
const webhookKeyBytes = Buffer.from("dodo oracle webhook key");
const webhookKey = `whsec_${webhookKeyBytes.toString("base64")}`;

async function packageVersion(name) {
  const packageJson = JSON.parse(await readFile(
    new URL(`node_modules/${name}/package.json`, import.meta.url),
    "utf8",
  ));
  return packageJson.version;
}

function fakeClient(overrides = {}) {
  return {
    baseURL: "https://test.dodopayments.com",
    bearerToken: "dodo_bearer_oracle",
    customers: {
      create: vi.fn(),
      customerPortal: { create: vi.fn() },
      list: vi.fn(async () => ({ items: [] })),
      update: vi.fn(),
    },
    payments: { list: vi.fn() },
    subscriptions: { list: vi.fn() },
    usageEvents: { ingest: vi.fn(), list: vi.fn() },
    ...overrides,
  };
}

function install(use, options = {}) {
  const client = options.client ?? fakeClient();
  return {
    client,
    plugin: dodopayments({ client, use, ...options }),
  };
}

function endpointShape(endpoint) {
  return {
    cloneRequest: endpoint.options.cloneRequest,
    isAction: endpoint.options.metadata?.isAction,
    method: endpoint.options.method,
    middlewareCount: endpoint.options.use.length,
    path: endpoint.path,
    requireRequest: endpoint.options.requireRequest,
  };
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

function webhookSignature(id, timestamp, body) {
  return `v1,${createHmac("sha256", webhookKeyBytes)
    .update(`${id}.${timestamp}.${body}`)
    .digest("base64")}`;
}

function subscriptionWebhook(type = "subscription.active") {
  return {
    business_id: "business_1",
    type,
    timestamp: "2024-01-01T00:00:00.000Z",
    data: {
      payload_type: "Subscription",
      addons: [],
      billing: {
        city: null,
        country: "US",
        state: null,
        street: null,
        zipcode: null,
      },
      brand_id: "brand_1",
      cancel_at_next_billing_date: false,
      created_at: "2024-01-01T00:00:00.000Z",
      credit_entitlement_cart: [],
      currency: "USD",
      customer: { customer_id: "customer_1", email: "user@example.com", name: "User" },
      metadata: {},
      meter_credit_entitlement_cart: [],
      meters: [],
      next_billing_date: "2024-02-01T00:00:00.000Z",
      on_demand: false,
      payment_frequency_count: 1,
      payment_frequency_interval: "Month",
      previous_billing_date: "2024-01-01T00:00:00.000Z",
      product_id: "product_1",
      quantity: 1,
      recurring_pre_tax_amount: 1000,
      status: "active",
      subscription_id: "subscription_1",
      subscription_period_count: 1,
      subscription_period_interval: "Month",
      tax_inclusive: false,
      trial_period_days: 0,
    },
  };
}

async function callWebhook(endpoint, body, signature) {
  return endpoint({
    asResponse: true,
    context: { logger: { error: vi.fn(), info: vi.fn(), warn: vi.fn() } },
    request: new Request("https://auth.example.test/api/auth/dodopayments/webhooks", {
      body,
      headers: {
        "webhook-id": "webhook_1",
        "webhook-signature": signature,
        "webhook-timestamp": "1785585600",
      },
      method: "POST",
    }),
  });
}

async function callAuthenticated(endpoint, input = {}) {
  endpoint.options.use = endpoint.options.use.slice(1);
  return endpoint({
    asResponse: true,
    context: {
      internalAdapter: { updateUser: vi.fn(async () => undefined) },
      logger: { error: vi.fn(), info: vi.fn(), warn: vi.fn() },
      session: {
        session: { id: "session_1", userId: "user_1" },
        user: {
          dodoCustomerId: "customer_saved",
          email: "user@example.com",
          emailVerified: true,
          id: "user_1",
          name: "User",
        },
      },
    },
    headers: new Headers(),
    ...input,
  });
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("@dodopayments/better-auth@1.6.5 executable oracle", () => {
  test("pins the complete effective dependency and export surface", async () => {
    expect(await packageVersion("@dodopayments/better-auth")).toBe("1.6.5");
    expect(await packageVersion("@dodopayments/core")).toBe("0.3.14");
    expect(await packageVersion("dodopayments")).toBe("2.47.0");
    expect(await packageVersion("better-auth")).toBe("1.7.1");
    expect(await packageVersion("zod")).toBe("4.4.3");
    expect(Object.keys(dodoRootExports).sort()).toEqual([
      "checkout",
      "dodopayments",
      "dodopaymentsClient",
      "portal",
      "usage",
      "webhooks",
    ]);
    expect(Object.keys(dodoClientExports)).toEqual(["dodopaymentsClient"]);
    expect(dodoClientExports.dodopaymentsClient).toBe(dodopaymentsClient);
    expect(dodopaymentsClient()).toEqual({
      id: "dodopayments-client",
      $InferServerPlugin: {},
    });
  });

  test("registers only selected contributions and requires the use array", () => {
    expect(install([]).plugin.endpoints).toEqual({});
    expect(Object.keys(install([checkout()]).plugin.endpoints)).toEqual([
      "dodoCheckout",
      "dodoCheckoutSession",
    ]);
    expect(Object.keys(install([portal()]).plugin.endpoints)).toEqual([
      "dodoPortal",
      "dodoSubscriptions",
      "dodoPayments",
    ]);
    expect(Object.keys(install([usage()]).plugin.endpoints)).toEqual([
      "dodoUsageIngest",
      "dodoUsageMetersList",
    ]);
    expect(Object.keys(install([webhooks({ webhookKey })]).plugin.endpoints))
      .toEqual(["dodopaymentsWebhooks"]);
    expect(() => dodopayments({ client: fakeClient() }))
      .toThrow("Cannot read properties of undefined (reading 'map')");
  });

  test("pins all eight endpoint descriptors and webhook action metadata", () => {
    const endpoints = install([
      checkout(),
      portal(),
      usage(),
      webhooks({ webhookKey }),
    ]).plugin.endpoints;
    expect(Object.fromEntries(Object.entries(endpoints).map(([name, endpoint]) => [
      name,
      endpointShape(endpoint),
    ]))).toEqual({
      dodoCheckout: {
        cloneRequest: undefined,
        isAction: undefined,
        method: "POST",
        middlewareCount: 1,
        path: "/dodopayments/checkout",
        requireRequest: true,
      },
      dodoCheckoutSession: {
        cloneRequest: undefined,
        isAction: undefined,
        method: "POST",
        middlewareCount: 1,
        path: "/dodopayments/checkout-session",
        requireRequest: true,
      },
      dodoPortal: {
        cloneRequest: undefined,
        isAction: undefined,
        method: "GET",
        middlewareCount: 2,
        path: "/dodopayments/customer/portal",
        requireRequest: undefined,
      },
      dodoSubscriptions: {
        cloneRequest: undefined,
        isAction: undefined,
        method: "GET",
        middlewareCount: 2,
        path: "/dodopayments/customer/subscriptions/list",
        requireRequest: undefined,
      },
      dodoPayments: {
        cloneRequest: undefined,
        isAction: undefined,
        method: "GET",
        middlewareCount: 2,
        path: "/dodopayments/customer/payments/list",
        requireRequest: undefined,
      },
      dodoUsageIngest: {
        cloneRequest: undefined,
        isAction: undefined,
        method: "POST",
        middlewareCount: 2,
        path: "/dodopayments/usage/ingest",
        requireRequest: undefined,
      },
      dodoUsageMetersList: {
        cloneRequest: undefined,
        isAction: undefined,
        method: "GET",
        middlewareCount: 2,
        path: "/dodopayments/usage/meters/list",
        requireRequest: undefined,
      },
      dodopaymentsWebhooks: {
        cloneRequest: true,
        isAction: false,
        method: "POST",
        middlewareCount: 1,
        path: "/dodopayments/webhooks",
        requireRequest: undefined,
      },
    });
  });

  test("publishes the exact user schema and database-hook shape", () => {
    const plugin = install([]).plugin;
    expect(plugin.id).toBe("dodopayments");
    expect(plugin.schema).toEqual({
      user: {
        fields: {
          dodoCustomerId: { input: false, required: false, type: "string" },
        },
      },
    });
    const hooks = plugin.init().options.databaseHooks.user;
    expect(Object.keys(hooks)).toEqual(["create", "update"]);
    expect(Object.keys(hooks.create)).toEqual(["after"]);
    expect(Object.keys(hooks.update)).toEqual(["after"]);
  });

  test("retains the pinned checkout, usage, and query-schema quirks", () => {
    const endpoints = install([checkout(), portal(), usage()]).plugin.endpoints;
    expect(endpoints.dodoCheckout.options.body.parse({
      billing: { city: "City", country: "US", extra: "stripped", state: "State", street: "Street", zipcode: "Zip" },
      customer: { email: "user@example.com", extra: "stripped" },
      discount_code: "ONE",
      discount_codes: ["TWO"],
      future_field: { retained: true },
      product_id: "product_1",
      referenceId: "reference_1",
    })).toEqual({
      billing: { city: "City", country: "US", state: "State", street: "Street", zipcode: "Zip" },
      customer: { email: "user@example.com" },
      discount_code: "ONE",
      discount_codes: ["TWO"],
      future_field: { retained: true },
      product_id: "product_1",
      referenceId: "reference_1",
    });
    expect(endpoints.dodoCheckoutSession.options.body.parse({ unknown: true }))
      .toEqual({});
    expect(endpoints.dodoUsageIngest.options.body.parse({
      event_id: "event_1",
      event_name: "tokens",
      metadata: null,
      timestamp: "2026-08-01T12:34:56+02:00",
      unknown: true,
    })).toEqual({
      event_id: "event_1",
      event_name: "tokens",
      metadata: null,
      timestamp: "2026-08-01T10:34:56.000Z",
    });
    expect(endpoints.dodoSubscriptions.options.query.parse({
      limit: "10",
      page: "0",
      status: "active",
    })).toEqual({ limit: 10, page: 0, status: "active" });
    expect(endpoints.dodoPayments.options.query.safeParse({ status: "refunded" }).success)
      .toBe(false);
  });

  test("preserves checkout validation and slug-resolution error precedence", async () => {
    const plugin = install([
      checkout({ authenticatedUsersOnly: true, products: [] }),
    ]).plugin;
    const validation = await invokeServer(plugin, "/dodopayments/checkout", { body: {} });
    expect(validation.status).toBe(400);
    expect(await validation.json()).toEqual({
      code: "VALIDATION_ERROR",
      message: "[body.billing] Required; [body.customer] Required",
    });
    const missingProduct = await invokeServer(plugin, "/dodopayments/checkout", {
      body: {
        billing: { city: "City", country: "US", state: "State", street: "Street", zipcode: "Zip" },
        customer: {},
        slug: "missing",
      },
    });
    expect(missingProduct.status).toBe(400);
    expect(await missingProduct.json()).toEqual({ message: "Product not found" });
    const invalidStatus = await invokeServer(
      install([portal()]).plugin,
      "/dodopayments/customer/payments/list?status=refunded",
      { method: "GET" },
    );
    expect(invalidStatus.status).toBe(400);
    expect(await invalidStatus.json()).toEqual({
      code: "VALIDATION_ERROR",
      message: "[query.status] Invalid enum value. Expected 'succeeded' | 'failed' | 'cancelled' | 'processing' | 'requires_customer_action' | 'requires_merchant_action' | 'requires_payment_method' | 'requires_confirmation' | 'requires_capture' | 'partially_captured' | 'partially_captured_and_capturable', received 'refunded'",
    });
    const missingCart = await invokeServer(plugin, "/dodopayments/checkout-session", {
      body: {},
    });
    expect(missingCart.status).toBe(401);
    expect(await missingCart.json()).toEqual({
      message: "You must be logged in to checkout",
    });
    const publicPlugin = install([checkout()]).plugin;
    const publicMissingCart = await invokeServer(
      publicPlugin,
      "/dodopayments/checkout-session",
      { body: {} },
    );
    expect(publicMissingCart.status).toBe(400);
    expect(await publicMissingCart.json()).toEqual({
      message: "Neither product_cart nor slug was provided",
    });
  });

  test("dynamic product resolver rejection escapes as an empty HTTP 500", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const plugin = install([checkout({
      products: async () => { throw new Error("resolver exploded"); },
    })]).plugin;
    const response = await invokeServer(plugin, "/dodopayments/checkout", {
      body: {
        billing: { city: "City", country: "US", state: "State", street: "Street", zipcode: "Zip" },
        customer: {},
        slug: "pro",
      },
    });
    expect(response.status).toBe(500);
    expect(await response.text()).toBe("");
  });

  test("dynamic checkout constructs a fresh pinned SDK client and preserves merge precedence", async () => {
    const { requests } = captureFetch((request) => {
      if (new URL(request.url).pathname.startsWith("/products/")) {
        return Response.json({ is_recurring: false, product_id: "product_1" });
      }
      return Response.json({ payment_link: "https://checkout.example.test/payment_1" });
    });
    const endpoint = install([
      checkout({ successUrl: "/checkout/success" }),
    ]).plugin.endpoints.dodoCheckout;
    const response = await endpoint({
      asResponse: true,
      body: {
        billing: { city: "City", country: "US", state: "State", street: "Street", zipcode: "Zip" },
        customer: { email: "body@example.com" },
        metadata: { referenceId: "metadata-wins" },
        product_id: "product_1",
        referenceId: "synthesized",
        return_url: "https://caller.example.test/legacy-return",
      },
      context: {
        logger: { error: vi.fn(), info: vi.fn(), warn: vi.fn() },
        session: {
          session: { id: "session_1" },
          user: { email: "session@example.com", id: "user_1", name: "Session User" },
        },
      },
      headers: new Headers(),
      request: new Request("https://auth.example.test/api/auth/dodopayments/checkout", {
        method: "POST",
      }),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      redirect: true,
      url: "https://checkout.example.test/payment_1",
    });
    expect(requests.map(({ method, url }) => ({ method, url }))).toEqual([
      { method: "GET", url: "https://test.dodopayments.com/products/product_1" },
      { method: "POST", url: "https://test.dodopayments.com/payments" },
    ]);
    expect(requests.every(request => request.headers.authorization === "Bearer dodo_bearer_oracle"))
      .toBe(true);
    expect(requests.every(request => request.headers["user-agent"] === "DodoPayments/JS 2.47.0"))
      .toBe(true);
    expect(JSON.parse(requests[1].body)).toEqual({
      billing: { city: "City", country: "US", state: "State", street: "Street", zipcode: "Zip" },
      customer: { email: "body@example.com", name: "Session User" },
      metadata: { referenceId: "metadata-wins" },
      payment_link: true,
      product_cart: [{ product_id: "product_1", quantity: 1 }],
      return_url: "https://caller.example.test/legacy-return",
    });
  });

  test("async slug resolution drives recurring quantity and discards caller cart identity", async () => {
    const products = vi.fn(async () => [{ productId: "subscription_product", slug: "pro" }]);
    const { requests } = captureFetch((request) => {
      if (new URL(request.url).pathname.startsWith("/products/")) {
        return Response.json({ is_recurring: true, product_id: "subscription_product" });
      }
      return Response.json({ payment_link: "https://checkout.example.test/subscription_1" });
    });
    const endpoint = install([checkout({ products })]).plugin.endpoints.dodoCheckout;
    const response = await endpoint({
      asResponse: true,
      body: {
        billing: { city: "City", country: "US", state: "State", street: "Street", zipcode: "Zip" },
        customer: { email: "user@example.com" },
        product_cart: [{ product_id: "caller_product", quantity: 9 }],
        product_id: "also_discarded",
        quantity: 3,
        slug: "pro",
      },
      context: { logger: { error: vi.fn() }, session: null },
      headers: new Headers(),
      request: new Request("https://auth.example.test/api/auth/dodopayments/checkout", { method: "POST" }),
    });
    expect(await response.json()).toEqual({
      redirect: true,
      url: "https://checkout.example.test/subscription_1",
    });
    expect(products).toHaveBeenCalledTimes(1);
    expect(requests.map(({ method, url }) => ({ method, url }))).toEqual([
      { method: "GET", url: "https://test.dodopayments.com/products/subscription_product" },
      { method: "POST", url: "https://test.dodopayments.com/subscriptions" },
    ]);
    expect(JSON.parse(requests[1].body)).toEqual({
      billing: { city: "City", country: "US", state: "State", street: "Street", zipcode: "Zip" },
      customer: { email: "user@example.com" },
      payment_link: true,
      product_id: "subscription_product",
      quantity: 3,
    });
  });

  test("checkout-session replaces signed-in customer and always overwrites caller return_url", async () => {
    const { requests } = captureFetch(() => Response.json({
      checkout_url: "https://checkout.example.test/session_1",
      session_id: "session_1",
    }));
    const call = async (endpoint, body, session) => endpoint({
      asResponse: true,
      body,
      context: { logger: { error: vi.fn() }, session },
      headers: new Headers(),
      request: new Request("https://auth.example.test/api/auth/dodopayments/checkout-session", { method: "POST" }),
    });
    const signedIn = install([checkout({ successUrl: "/configured-return" })])
      .plugin.endpoints.dodoCheckoutSession;
    await call(signedIn, {
      customer: { email: "caller@example.com", name: "Caller", phone_number: "+1" },
      product_cart: [{ product_id: "product_1", quantity: 1 }],
      return_url: "https://caller.example.test/ignored",
    }, {
      session: { id: "session_1" },
      user: { email: "session@example.com", id: "user_1", name: "Session User" },
    });
    const anonymous = install([checkout()]).plugin.endpoints.dodoCheckoutSession;
    await call(anonymous, {
      customer: { email: "caller@example.com" },
      product_cart: [{ product_id: "product_2", quantity: 2 }],
      return_url: "https://caller.example.test/also-ignored",
    }, null);
    expect(JSON.parse(requests[0].body)).toEqual({
      customer: { email: "session@example.com", name: "Session User" },
      product_cart: [{ product_id: "product_1", quantity: 1 }],
      return_url: "https://auth.example.test/configured-return",
    });
    expect(JSON.parse(requests[1].body)).toEqual({
      customer: { email: "caller@example.com" },
      product_cart: [{ product_id: "product_2", quantity: 2 }],
    });
  });

  test("discount mutual exclusion rejects before either provider path and then rewrites", async () => {
    const { requests } = captureFetch(() => Response.json({
      is_recurring: false,
      product_id: "product_1",
    }));
    const legacy = install([checkout()]).plugin.endpoints.dodoCheckout;
    const legacyResponse = await legacy({
      asResponse: true,
      body: {
        billing: { city: "City", country: "US", state: "State", street: "Street", zipcode: "Zip" },
        customer: {},
        discount_code: "ONE",
        discount_codes: ["TWO"],
        product_id: "product_1",
      },
      context: { logger: { error: vi.fn() }, session: null },
      headers: new Headers(),
      request: new Request("https://auth.example.test/api/auth/dodopayments/checkout", { method: "POST" }),
    });
    expect(legacyResponse.status).toBe(500);
    expect(await legacyResponse.json()).toEqual({ message: "Checkout creation failed" });
    expect(requests).toHaveLength(0);

    const session = install([checkout()]).plugin.endpoints.dodoCheckoutSession;
    const sessionResponse = await session({
      asResponse: true,
      body: {
        discount_code: "ONE",
        discount_codes: ["TWO"],
        product_cart: [{ product_id: "product_1", quantity: 1 }],
      },
      context: { logger: { error: vi.fn() }, session: null },
      headers: new Headers(),
      request: new Request("https://auth.example.test/api/auth/dodopayments/checkout-session", { method: "POST" }),
    });
    expect(sessionResponse.status).toBe(500);
    expect(await sessionResponse.json()).toEqual({
      message: "Checkout session creation failed",
    });
    expect(requests).toHaveLength(0);
  });

  test("customer hooks create, reuse, backfill, and contain update failures exactly", async () => {
    const updateUser = vi.fn(async () => undefined);
    const logger = { error: vi.fn(), info: vi.fn(), warn: vi.fn() };
    const client = fakeClient();
    client.customers.create.mockResolvedValue({ customer_id: "customer_new" });
    const params = vi.fn(async () => ({
      metadata: { source: "auth" },
      phone_number: "+441234",
    }));
    const plugin = install([], {
      client,
      createCustomerOnSignUp: true,
      getCustomerParams: params,
    }).plugin;
    const hooks = plugin.init().options.databaseHooks.user;
    const ctx = { context: { internalAdapter: { updateUser }, logger } };
    const user = { email: "user@example.com", id: "user_1", name: "User" };

    await hooks.create.after(user, ctx);
    expect(client.customers.create).toHaveBeenCalledWith({
      email: "user@example.com",
      metadata: { source: "auth" },
      name: "User",
      phone_number: "+441234",
    }, { idempotencyKey: "user_1" });
    expect(updateUser).toHaveBeenCalledWith("user_1", {
      dodoCustomerId: "customer_new",
    });

    client.customers.list.mockResolvedValue({ items: [{ customer_id: "customer_existing" }] });
    await hooks.update.after(user, ctx);
    expect(updateUser).toHaveBeenLastCalledWith("user_1", {
      dodoCustomerId: "customer_existing",
    });
    expect(client.customers.update).toHaveBeenLastCalledWith("customer_existing", {
      metadata: { source: "auth" },
      name: "User",
      phone_number: "+441234",
    });

    client.customers.update.mockRejectedValueOnce(new Error("provider unavailable"));
    await expect(hooks.update.after({ ...user, dodoCustomerId: "customer_direct" }, ctx))
      .resolves.toBeUndefined();
    expect(logger.error).toHaveBeenLastCalledWith(
      "DodoPayments customer update failed. Error: provider unavailable",
    );
  });

  test("authenticated portal and usage handlers retain exact provider payloads and paging", async () => {
    const client = fakeClient();
    client.customers.customerPortal.create.mockResolvedValue({ link: "https://portal.example.test" });
    client.subscriptions.list.mockResolvedValue({ items: [{ subscription_id: "subscription_1" }] });
    client.payments.list.mockResolvedValue({ items: [{ payment_id: "payment_1" }] });
    client.usageEvents.ingest.mockResolvedValue({ ingested_count: 1 });
    client.usageEvents.list.mockResolvedValue({ items: [{ meter_id: "meter_1" }] });
    const endpoints = install([portal(), usage()], { client }).plugin.endpoints;

    const portalResponse = await callAuthenticated(endpoints.dodoPortal);
    expect(await portalResponse.json()).toEqual({
      redirect: true,
      url: "https://portal.example.test",
    });
    expect(client.customers.customerPortal.create).toHaveBeenCalledWith("customer_saved");
    expect(client.customers.list).not.toHaveBeenCalled();

    const subscriptions = await callAuthenticated(endpoints.dodoSubscriptions, {
      query: { limit: "10", page: "0", status: "active" },
    });
    expect(await subscriptions.json()).toEqual({
      items: [{ subscription_id: "subscription_1" }],
    });
    expect(client.subscriptions.list).toHaveBeenCalledWith({
      customer_id: "customer_saved",
      page_number: undefined,
      page_size: 10,
      status: "active",
    });

    const payments = await callAuthenticated(endpoints.dodoPayments, {
      query: { limit: "5", page: "2", status: "succeeded" },
    });
    expect(await payments.json()).toEqual({ items: [{ payment_id: "payment_1" }] });
    expect(client.payments.list).toHaveBeenCalledWith({
      customer_id: "customer_saved",
      page_number: 1,
      page_size: 5,
      status: "succeeded",
    });

    const ingest = await callAuthenticated(endpoints.dodoUsageIngest, {
      body: {
        event_id: "event_1",
        event_name: "tokens",
        metadata: { amount: 2, cached: false },
        timestamp: "2026-08-01T12:34:56+02:00",
      },
    });
    expect(await ingest.json()).toEqual({ ingested_count: 1 });
    expect(client.usageEvents.ingest).toHaveBeenCalledWith({
      events: [{
        customer_id: "customer_saved",
        event_id: "event_1",
        event_name: "tokens",
        metadata: { amount: 2, cached: false },
        timestamp: "2026-08-01T10:34:56.000Z",
      }],
    });

    const meters = await callAuthenticated(endpoints.dodoUsageMetersList, {
      query: { event_name: "tokens", meter_id: "meter_1", page_number: "3", page_size: "4" },
    });
    expect(await meters.json()).toEqual({ items: [{ meter_id: "meter_1" }] });
    expect(client.usageEvents.list).toHaveBeenCalledWith({
      customer_id: "customer_saved",
      event_name: "tokens",
      meter_id: "meter_1",
      page_number: 3,
      page_size: 4,
    });
  });

  test("customer creation failures are fatal while async ID persistence failures are warnings", async () => {
    const providerFailure = fakeClient();
    providerFailure.customers.list.mockRejectedValue(new Error("list failed"));
    const fatalHook = install([], {
      client: providerFailure,
      createCustomerOnSignUp: true,
    }).plugin.init().options.databaseHooks.user.create.after;
    await expect(fatalHook(
      { email: "user@example.com", id: "user_1", name: "User" },
      { context: { internalAdapter: { updateUser: vi.fn() }, logger: { warn: vi.fn() } } },
    )).rejects.toMatchObject({
      body: { message: "DodoPayments customer creation failed. Error: list failed" },
      status: "INTERNAL_SERVER_ERROR",
      statusCode: 500,
    });

    const logger = { warn: vi.fn() };
    const persistenceFailure = fakeClient();
    persistenceFailure.customers.create.mockResolvedValue({ customer_id: "customer_new" });
    const warningHook = install([], {
      client: persistenceFailure,
      createCustomerOnSignUp: true,
    }).plugin.init().options.databaseHooks.user.create.after;
    await warningHook(
      { email: "user@example.com", id: "user_1", name: "User" },
      {
        context: {
          internalAdapter: { updateUser: vi.fn(async () => { throw new Error("write failed"); }) },
          logger,
        },
      },
    );
    await new Promise(setImmediate);
    expect(logger.warn).toHaveBeenCalledWith(
      "DodoPayments: failed to store dodoCustomerId for user user_1. Error: write failed",
    );
  });

  test("official client uses the exact Dodo Payments namespaces, methods, and query casing", async () => {
    const { requests } = captureFetch(() => Response.json({ ok: true }));
    const client = createAuthClient({
      baseURL: "https://auth.example.test",
      fetchOptions: { customFetchImpl: globalThis.fetch },
      plugins: [dodopaymentsClient()],
    });
    await client.dodopayments.checkout({ slug: "pro" });
    await client.dodopayments.checkoutSession({
      product_cart: [{ product_id: "product_1", quantity: 2 }],
    });
    await client.dodopayments.customer.portal();
    await client.dodopayments.customer.subscriptions.list({
      query: { limit: 3, page: 2, status: "active" },
    });
    await client.dodopayments.customer.payments.list({ query: { page: 1 } });
    await client.dodopayments.usage.ingest({ event_id: "event_1", event_name: "tokens" });
    await client.dodopayments.usage.meters.list({
      query: { event_name: "tokens", page_number: 4 },
    });
    expect(requests.map(({ body, method, url }) => ({ body, method, url }))).toEqual([
      { body: "{\"slug\":\"pro\"}", method: "POST", url: "https://auth.example.test/api/auth/dodopayments/checkout" },
      { body: "{\"product_cart\":[{\"product_id\":\"product_1\",\"quantity\":2}]}", method: "POST", url: "https://auth.example.test/api/auth/dodopayments/checkout-session" },
      { body: null, method: "GET", url: "https://auth.example.test/api/auth/dodopayments/customer/portal" },
      { body: null, method: "GET", url: "https://auth.example.test/api/auth/dodopayments/customer/subscriptions/list?limit=3&page=2&status=active" },
      { body: null, method: "GET", url: "https://auth.example.test/api/auth/dodopayments/customer/payments/list?page=1" },
      { body: "{\"event_id\":\"event_1\",\"event_name\":\"tokens\"}", method: "POST", url: "https://auth.example.test/api/auth/dodopayments/usage/ingest" },
      { body: null, method: "GET", url: "https://auth.example.test/api/auth/dodopayments/usage/meters/list?event_name=tokens&page_number=4" },
    ]);
  });

  test("webhook verification dispatches generic then typed callbacks with transformed dates", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-01T12:00:00.000Z"));
    const calls = [];
    const endpoint = install([webhooks({
      onPayload: async payload => calls.push(["payload", payload]),
      onSubscriptionActive: async payload => calls.push(["active", payload]),
      webhookKey,
    })]).plugin.endpoints.dodopaymentsWebhooks;
    const body = JSON.stringify(subscriptionWebhook());
    const signature = webhookSignature("webhook_1", "1785585600", body);
    const response = await callWebhook(endpoint, body, signature);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ received: true });
    expect(calls.map(([name]) => name)).toEqual(["payload", "active"]);
    expect(calls[0][1]).toBe(calls[1][1]);
    expect(calls[0][1].timestamp).toBeInstanceOf(Date);
    expect(calls[0][1].data.created_at).toBeInstanceOf(Date);
  });

  test("webhook failures preserve the exact verification and callback error contracts", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-01T12:00:00.000Z"));
    const body = JSON.stringify(subscriptionWebhook());
    const signature = webhookSignature("webhook_1", "1785585600", body);

    const missingKey = install([webhooks({ webhookKey: "" })])
      .plugin.endpoints.dodopaymentsWebhooks;
    const missingKeyResponse = await callWebhook(missingKey, body, signature);
    expect(missingKeyResponse.status).toBe(400);
    expect(await missingKeyResponse.json()).toEqual({
      message: "Webhook Error: DodoPayments webhook webhookKey not found",
    });

    const invalid = install([webhooks({ webhookKey })])
      .plugin.endpoints.dodopaymentsWebhooks;
    const invalidResponse = await callWebhook(invalid, body, "v1,invalid");
    expect(invalidResponse.status).toBe(400);
    expect(await invalidResponse.json()).toEqual({
      message: "Webhook Error: No matching signature found",
    });

    const active = vi.fn();
    const callbackFailure = install([webhooks({
      onPayload: async () => { throw new Error("callback exploded"); },
      onSubscriptionActive: active,
      webhookKey,
    })]).plugin.endpoints.dodopaymentsWebhooks;
    const callbackResponse = await callWebhook(callbackFailure, body, signature);
    expect(callbackResponse.status).toBe(400);
    expect(await callbackResponse.json()).toEqual({
      message: "Webhook error: See server logs for more information.",
    });
    expect(active).not.toHaveBeenCalled();
  });
});
