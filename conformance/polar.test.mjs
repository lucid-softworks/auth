import * as polarRoot from "@polar-sh/better-auth";
import * as polarClientSubpath from "@polar-sh/better-auth/client";
import { createAuthClient } from "better-auth/client";
import { readFile } from "node:fs/promises";
import { describe, expect, test, vi } from "vitest";

const {
  CheckoutParams,
  checkout,
  polar,
  polarClient,
  portal,
  usage,
  webhooks,
} = polarRoot;

function fakePolar(overrides = {}) {
  return {
    checkouts: { create: vi.fn(async () => ({ url: "https://buy.polar.sh/x" })) },
    customerPortal: {
      benefitGrants: { list: vi.fn(async () => ({ result: { items: [] } })) },
      customerMeters: { list: vi.fn(async () => ({ result: { items: [] } })) },
      orders: { list: vi.fn(async () => ({ result: { items: [] } })) },
      subscriptions: { list: vi.fn(async () => ({ result: { items: [] } })) },
    },
    customers: {
      create: vi.fn(async (value) => ({ id: "cus_new", ...value })),
      delete: vi.fn(async () => undefined),
      getStateExternal: vi.fn(async () => ({ activeSubscriptions: [] })),
      list: vi.fn(async () => ({ result: { items: [] } })),
      update: vi.fn(async () => ({ id: "cus_1", externalId: "user_1" })),
      updateExternal: vi.fn(async () => ({ id: "cus_1" })),
    },
    customerSessions: {
      create: vi.fn(async () => ({
        customerPortalUrl: "https://polar.sh/portal",
        token: "portal_token",
      })),
    },
    events: { ingest: vi.fn(async () => ({ inserted: 1 })) },
    subscriptions: { list: vi.fn(async () => ({ result: { items: [] } })) },
    ...overrides,
  };
}

function install(use, options = {}) {
  const client = options.client ?? fakePolar();
  return {
    client,
    plugin: polar({ client, use, ...options }),
  };
}

function endpointShape(endpoint) {
  return {
    cloneRequest: endpoint.options.cloneRequest,
    isAction: endpoint.options.metadata?.isAction,
    method: endpoint.options.method,
    path: endpoint.path,
  };
}

function context(session) {
  return {
    baseURL: "https://auth.example.test/api/auth",
    logger: { error: vi.fn(), info: vi.fn(), warn: vi.fn() },
    options: { baseURL: "https://auth.example.test/api/auth" },
    session,
  };
}

function installEmbedDom(origin = "https://app.example.test") {
  const previousWindow = globalThis.window;
  const previousDocument = globalThis.document;
  let messageListener;
  const children = [];
  const element = (tag) => ({
    tag,
    style: {},
    appendChild() {},
  });
  const body = {
    classList: { add() {}, remove() {} },
    appendChild(child) { children.push(child); },
    contains(child) { return children.includes(child); },
    removeChild(child) {
      const index = children.indexOf(child);
      if (index >= 0) children.splice(index, 1);
    },
  };
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      location: { origin },
      parent: { postMessage() {} },
      addEventListener(type, listener) {
        if (type === "message") messageListener = listener;
      },
      removeEventListener() {},
    },
  });
  Object.defineProperty(globalThis, "document", {
    configurable: true,
    value: {
      body,
      head: { appendChild() {} },
      createElement: element,
    },
  });
  return {
    children,
    loaded() {
      expect(messageListener).toBeTypeOf("function");
      messageListener({
        origin: "https://polar.sh",
        data: { type: "POLAR_CHECKOUT", event: "loaded" },
      });
    },
    restore() {
      if (previousWindow === undefined) delete globalThis.window;
      else Object.defineProperty(globalThis, "window", {
        configurable: true,
        value: previousWindow,
      });
      if (previousDocument === undefined) delete globalThis.document;
      else Object.defineProperty(globalThis, "document", {
        configurable: true,
        value: previousDocument,
      });
    },
  };
}

describe("@polar-sh/better-auth@1.8.4 oracle", () => {
  test("pins the adapter and SDK selected with Better Auth 1.7.2", async () => {
    const adapterPackage = JSON.parse(
      await readFile(
        new URL("node_modules/@polar-sh/better-auth/package.json", import.meta.url),
        "utf8",
      ),
    );
    const sdkPackage = JSON.parse(
      await readFile(
        new URL("node_modules/@polar-sh/sdk/package.json", import.meta.url),
        "utf8",
      ),
    );
    expect(adapterPackage.version).toBe("1.8.4");
    expect(adapterPackage.peerDependencies["better-auth"]).toBe("^1.4.12");
    expect(sdkPackage.version).toBe("0.47.1");
  });

  test("exports only the pinned runtime package surface", () => {
    expect(Object.keys(polarRoot).sort()).toEqual([
      "CheckoutParams",
      "checkout",
      "polar",
      "polarClient",
      "portal",
      "usage",
      "webhooks",
    ]);
    expect(Object.keys(polarClientSubpath)).toEqual(["polarClient"]);
    expect(polarClientSubpath.polarClient).toBe(polarClient);
    expect(polarClient()).toMatchObject({ id: "polar-client" });
    expect(Object.keys(polarClient())).toEqual([
      "id",
      "$InferServerPlugin",
      "getActions",
    ]);
  });

  test("registers only selected contributions and tolerates an empty list", () => {
    expect(install([]).plugin).toMatchObject({ id: "polar", endpoints: {} });
    expect(Object.keys(install([checkout()]).plugin.endpoints)).toEqual([
      "checkout",
    ]);
    expect(Object.keys(install([portal()]).plugin.endpoints)).toEqual([
      "portal",
      "state",
      "benefits",
      "subscriptions",
      "orders",
    ]);
    expect(Object.keys(install([usage()]).plugin.endpoints)).toEqual([
      "meters",
      "ingestion",
    ]);
    expect(Object.keys(install([webhooks({ secret: "secret" })]).plugin.endpoints))
      .toEqual(["polarWebhooks"]);
  });

  test("pins all endpoint methods, paths, and webhook action metadata", () => {
    const endpoints = install([
      checkout(),
      portal(),
      usage(),
      webhooks({ secret: "secret" }),
    ]).plugin.endpoints;
    expect(Object.fromEntries(Object.entries(endpoints).map(([key, value]) => [
      key,
      endpointShape(value),
    ]))).toEqual({
      checkout: { path: "/checkout", method: "POST", cloneRequest: undefined, isAction: undefined },
      portal: { path: "/customer/portal", method: ["GET", "POST"], cloneRequest: undefined, isAction: undefined },
      state: { path: "/customer/state", method: "GET", cloneRequest: undefined, isAction: undefined },
      benefits: { path: "/customer/benefits/list", method: "GET", cloneRequest: undefined, isAction: undefined },
      subscriptions: { path: "/customer/subscriptions/list", method: "GET", cloneRequest: undefined, isAction: undefined },
      orders: { path: "/customer/orders/list", method: "GET", cloneRequest: undefined, isAction: undefined },
      meters: { path: "/usage/meters/list", method: "GET", cloneRequest: undefined, isAction: undefined },
      ingestion: { path: "/usage/ingest", method: "POST", cloneRequest: undefined, isAction: undefined },
      polarWebhooks: { path: "/polar/webhooks", method: "POST", cloneRequest: true, isAction: false },
    });
  });

  test("checkout validation strips aliases and preserves JavaScript coercion", () => {
    expect(CheckoutParams.parse({
      allowDiscountCodes: "false",
      callbackUrl: "/wrong",
      redirect: "false",
      slug: "",
    })).toEqual({
      allowDiscountCodes: true,
      redirect: true,
      slug: "",
    });
    expect(CheckoutParams.safeParse({ embedOrigin: "/relative" }).success).toBe(false);
    expect(CheckoutParams.safeParse({ successUrl: "relative" }).success).toBe(false);
    expect(CheckoutParams.safeParse({ successUrl: "/relative" }).success).toBe(true);
    expect(CheckoutParams.safeParse({ trialIntervalCount: 0 }).success).toBe(false);
    expect(CheckoutParams.safeParse({ trialIntervalCount: 1001 }).success).toBe(false);
  });

  test("checkout metadata uses UTF-16 limits and exact entry caps", () => {
    expect(CheckoutParams.safeParse({ metadata: { ["x".repeat(41)]: true } }).success)
      .toBe(false);
    expect(CheckoutParams.safeParse({ metadata: { value: "x".repeat(501) } }).success)
      .toBe(false);
    expect(CheckoutParams.safeParse({
      metadata: Object.fromEntries(Array.from({ length: 51 }, (_, index) => [`k${index}`, index])),
    }).success).toBe(false);
    expect(CheckoutParams.safeParse({ metadata: { value: "😀".repeat(251) } }).success)
      .toBe(false);
  });

  test("checkout resolves slug before authenticated-user enforcement", async () => {
    const endpoint = install([
      checkout({ authenticatedUsersOnly: true, products: [{ productId: "p", slug: "pro" }] }),
    ]).plugin.endpoints.checkout;
    const response = await endpoint({
      asResponse: true,
      body: { slug: "missing" },
      context: context(undefined),
      headers: new Headers(),
      request: new Request("https://auth.example.test/api/auth/checkout", { method: "POST" }),
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ message: "Product not found" });
  });

  test("checkout product resolver failures escape the adapter checkout error rewrite", async () => {
    const endpoint = install([
      checkout({
        products: async () => {
          throw new Error("resolver exploded");
        },
      }),
    ]).plugin.endpoints.checkout;
    await expect(endpoint({
      asResponse: true,
      body: { slug: "pro" },
      context: context(undefined),
      headers: new Headers(),
      request: new Request("https://auth.example.test/api/auth/checkout", { method: "POST" }),
    })).rejects.toThrow("resolver exploded");
  });

  test("checkout spreads body metadata after referenceId and applies URL/theme defaults", async () => {
    const client = fakePolar();
    const endpoint = install([
      checkout({ products: [{ productId: "prod_1", slug: "pro" }], theme: "dark" }),
    ], { client }).plugin.endpoints.checkout;
    const response = await endpoint({
      asResponse: true,
      body: {
        metadata: { referenceId: "body-wins" },
        redirect: false,
        referenceId: "synthesized",
        returnUrl: "/return",
        slug: "pro",
        successUrl: "/success",
      },
      context: context(undefined),
      headers: new Headers(),
      request: new Request("https://auth.example.test/api/auth/checkout", { method: "POST" }),
    });
    expect(client.checkouts.create).toHaveBeenCalledWith(expect.objectContaining({
      allowDiscountCodes: true,
      metadata: { referenceId: "body-wins" },
      products: ["prod_1"],
      returnUrl: "https://auth.example.test/return",
      successUrl: "https://auth.example.test/success",
    }));
    expect(await response.json()).toEqual({
      redirect: false,
      url: "https://buy.polar.sh/x?theme=dark",
    });
  });

  test("portal construction parses returnUrl eagerly", () => {
    expect(() => portal({ returnUrl: "/relative" })(fakePolar())).toThrow();
    expect(() => portal({ returnUrl: "https://app.example.test/return" })(fakePolar()))
      .not.toThrow();
  });

  test("reference subscriptions forward an unvalidated referenceId and JS booleans", async () => {
    const client = fakePolar();
    const endpoint = install([portal()], { client }).plugin.endpoints.subscriptions;
    const response = await endpoint({
      asResponse: true,
      context: context({
        session: { id: "session_1", userId: "user_1" },
        user: { id: "user_1", isAnonymous: false },
      }),
      headers: new Headers(),
      query: { active: true, referenceId: "foreign-org" },
      request: new Request("https://auth.example.test/api/auth/customer/subscriptions/list"),
    });
    expect(response.status).toBe(200);
    expect(client.subscriptions.list).toHaveBeenCalledWith(expect.objectContaining({
      active: true,
      metadata: { referenceId: "foreign-org" },
    }));
  });

  test("webhook empty secret is rewritten to the exact 400 contract", async () => {
    const endpoint = install([webhooks({ secret: "" })]).plugin.endpoints.polarWebhooks;
    const response = await endpoint({
      asResponse: true,
      context: context(undefined),
      request: new Request("https://auth.example.test/api/auth/polar/webhooks", {
        body: "{}",
        headers: {
          "webhook-id": "id",
          "webhook-signature": "v1,invalid",
          "webhook-timestamp": "0",
        },
        method: "POST",
      }),
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({
      message: "Webhook Error: Polar webhook secret not found",
    });
  });

  test("official client uses the pinned route namespaces and methods", async () => {
    const requests = [];
    const client = createAuthClient({
      baseURL: "https://auth.example.test",
      fetchOptions: {
        customFetchImpl: async (input, init = {}) => {
          requests.push({ method: init.method, url: String(input), body: init.body });
          return Response.json({ result: { items: [] } });
        },
      },
      plugins: [polarClient()],
    });
    await client.checkout({ products: "prod" });
    await client.customer.portal();
    await client.customer.portal({ redirect: false });
    await client.customer.state();
    await client.customer.benefits.list({ query: { page: 2 } });
    await client.customer.subscriptions.list({ query: { referenceId: "ref" } });
    await client.customer.orders.list({ query: { limit: 3 } });
    await client.usage.meters.list({ query: { page: 4 } });
    await client.usage.ingest({ event: "tokens", metadata: { amount: 2 } });
    expect(requests.map(({ method, url }) => ({ method, url }))).toEqual([
      { method: "POST", url: "https://auth.example.test/api/auth/checkout" },
      { method: "GET", url: "https://auth.example.test/api/auth/customer/portal" },
      { method: "POST", url: "https://auth.example.test/api/auth/customer/portal" },
      { method: "GET", url: "https://auth.example.test/api/auth/customer/state" },
      { method: "GET", url: "https://auth.example.test/api/auth/customer/benefits/list?page=2" },
      { method: "GET", url: "https://auth.example.test/api/auth/customer/subscriptions/list?referenceId=ref" },
      { method: "GET", url: "https://auth.example.test/api/auth/customer/orders/list?limit=3" },
      { method: "GET", url: "https://auth.example.test/api/auth/usage/meters/list?page=4" },
      { method: "POST", url: "https://auth.example.test/api/auth/usage/ingest" },
    ]);
  });

  test("checkoutEmbed preserves the published transformation and fetch-option precedence", async () => {
    const dom = installEmbedDom();
    const fetch = vi.fn(async () => ({
      data: { url: "https://buy.polar.sh/native?theme=dark" },
      error: null,
    }));
    try {
      const action = polarClient().getActions(fetch).checkoutEmbed;
      const pending = action(
        { products: "product_1", redirect: true },
        { body: { runtimeOverride: true }, method: "PUT" },
      );
      await new Promise(setImmediate);
      dom.loaded();
      const embedded = await pending;
      expect(fetch).toHaveBeenCalledWith("/checkout", {
        method: "PUT",
        body: { runtimeOverride: true },
      });
      expect(embedded.iframe.src).toBe(
        "https://buy.polar.sh/native?theme=dark&embed=true&embed_origin=https%3A%2F%2Fapp.example.test",
      );
    } finally {
      dom.restore();
    }
  });

  test("checkoutEmbed throws an ordinary error and defaults an absent theme to light", async () => {
    const dom = installEmbedDom();
    try {
      const failure = polarClient().getActions(async () => ({
        data: null,
        error: { message: "checkout unavailable" },
      })).checkoutEmbed;
      await expect(failure({ products: ["p"] })).rejects.toThrow("checkout unavailable");

      const success = polarClient().getActions(async () => ({
        data: { url: "https://buy.polar.sh/no-theme" },
        error: null,
      })).checkoutEmbed;
      const pending = success({ products: "p" });
      await new Promise(setImmediate);
      dom.loaded();
      const embedded = await pending;
      expect(new URL(embedded.iframe.src).searchParams.get("theme")).toBe("light");
    } finally {
      dom.restore();
    }
  });
});
