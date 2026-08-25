import { autumn } from "autumn-js/better-auth";
import * as autumnServer from "autumn-js/better-auth";
import { createAutumnClient } from "autumn-js/react";
import * as autumnReact from "autumn-js/react";
import { betterAuth } from "better-auth";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { afterEach, describe, expect, test, vi } from "vitest";

const endpointPaths = {
  getOrCreateCustomer: "/v1/customers.get_or_create",
  getEntity: "/v1/entities.get",
  attach: "/v1/billing.attach",
  previewAttach: "/v1/billing.preview_attach",
  updateSubscription: "/v1/billing.update",
  previewUpdateSubscription: "/v1/billing.preview_update",
  openCustomerPortal: "/v1/billing.open_customer_portal",
  createReferralCode: "/v1/referrals.create_code",
  redeemReferralCode: "/v1/referrals.redeem_code",
  listPlans: "/v1/plans.list",
  listEvents: "/v1/events.list",
  aggregateEvents: "/v1/events.aggregate",
  multiAttach: "/v1/billing.multi_attach",
  previewMultiAttach: "/v1/billing.preview_multi_attach",
  setupPayment: "/v1/billing.setup_payment",
};

const require = createRequire(import.meta.url);

const validBodies = {
  getOrCreateCustomer: {},
  getEntity: { entityId: "entity_1" },
  attach: { planId: "plan_1" },
  previewAttach: { planId: "plan_1" },
  updateSubscription: {},
  previewUpdateSubscription: {},
  openCustomerPortal: {},
  createReferralCode: { programId: "program_1" },
  redeemReferralCode: { code: "REFERRAL" },
  listPlans: {},
  listEvents: {},
  aggregateEvents: { featureId: "feature_1" },
  multiAttach: { plans: [] },
  previewMultiAttach: { plans: [] },
  setupPayment: {},
};

const userSession = {
  session: { id: "session_1", userId: "user_1", activeOrganizationId: null },
  user: { id: "user_1", name: "Ada", email: "ada@example.test" },
};

function context(session = userSession, adapter = null) {
  return {
    adapter,
    logger: { error: vi.fn(), info: vi.fn(), warn: vi.fn() },
    session,
  };
}

async function invoke(endpoint, body, endpointContext = context()) {
  return endpoint({
    asResponse: true,
    body,
    context: endpointContext,
    headers: new Headers(),
    request: new Request(`https://auth.example.test/api/auth${endpoint.path}`, {
      body: JSON.stringify(body),
      headers: { "content-type": "application/json" },
      method: "POST",
    }),
  });
}

async function invokeServer(plugin, route, body) {
  const auth = betterAuth({
    baseURL: "https://auth.example.test",
    plugins: [plugin],
    secret: "01234567890123456789012345678901",
  });
  return auth.handler(new Request(
    `https://auth.example.test/api/auth/autumn/${route}`,
    {
      body: JSON.stringify(body),
      headers: { "content-type": "application/json" },
      method: "POST",
    },
  ));
}

function captureRequests(response = () => Response.json(
  { message: "captured", code: "captured" },
  { status: 422 },
)) {
  const requests = [];
  const fetch = vi.fn(async (input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    requests.push({
      body: request.body ? JSON.parse(await request.clone().text()) : undefined,
      credentials: request.credentials,
      headers: Object.fromEntries(request.headers),
      method: request.method,
      url: request.url,
    });
    return response(request);
  });
  vi.stubGlobal("fetch", fetch);
  return { fetch, requests };
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  delete process.env.AUTUMN_SECRET_KEY;
});

describe("autumn-js@1.2.53 Better Auth oracle", () => {
  test("pins the immutable package and its exact public exports", async () => {
    const packageJson = JSON.parse(await readFile(
      new URL("node_modules/autumn-js/package.json", import.meta.url),
      "utf8",
    ));
    expect(packageJson.version).toBe("1.2.53");
    expect(Object.keys(autumnServer)).toEqual(["autumn"]);
    expect(Object.keys(autumnReact).sort()).toEqual([
      "AutumnClientError",
      "AutumnProvider",
      "createAutumnClient",
      "useAggregateEvents",
      "useAutumnClient",
      "useCustomer",
      "useEntity",
      "useListEvents",
      "useListPlans",
      "useReferrals",
    ]);
    expect(() => require.resolve("autumn-js/better-auth/client")).toThrow(
      expect.objectContaining({ code: "ERR_PACKAGE_PATH_NOT_EXPORTED" }),
    );
  });

  test("publishes exactly fifteen POST endpoints and no client or state metadata", () => {
    const plugin = autumn({ secretKey: "secret" });
    expect(Object.keys(plugin)).toEqual(["id", "endpoints"]);
    expect(plugin.id).toBe("autumn");
    expect(Object.keys(plugin.endpoints)).toEqual(Object.keys(endpointPaths));
    expect(Object.fromEntries(Object.entries(plugin.endpoints).map(([name, endpoint]) => [
      name,
      { method: endpoint.options.method, path: endpoint.path },
    ]))).toEqual(Object.fromEntries(Object.keys(endpointPaths).map(name => [
      name,
      { method: "POST", path: `/autumn/${name}` },
    ])));
  });

  test("public schemas strip protected identities and preserve pinned defaults", () => {
    const endpoints = autumn({ secretKey: "secret" }).endpoints;
    for (const [name, endpoint] of Object.entries(endpoints)) {
      const parsed = endpoint.options.body.parse({
        ...validBodies[name],
        customerId: "spoofed_customer",
        customerData: { customerId: "spoofed_nested" },
      });
      if (name === "listPlans" || name === "listEvents") {
        expect(parsed.customerId, name).toBe("spoofed_customer");
      } else {
        expect(parsed, name).not.toHaveProperty("customerId");
      }
      expect(parsed, name).not.toHaveProperty("customerData");
    }
    expect(endpoints.getOrCreateCustomer.options.body.parse({})).toEqual({
      errorOnNotFound: true,
    });
    expect(endpoints.listPlans.options.body.parse(undefined)).toBeUndefined();
    expect(endpoints.listEvents.options.body.parse(undefined)).toBeUndefined();
    expect(endpoints.aggregateEvents.options.body.safeParse({
      featureId: "feature_1",
      range: 123,
    }).success).toBe(true);
  });

  test("body and context resolution precede the secret and identity callback exactly", async () => {
    const identify = vi.fn(async () => ({ customerId: "identified" }));
    const findOne = vi.fn(async () => ({ id: "org_1", name: "Org" }));
    const endpoints = autumn({ identify }).endpoints;
    const active = structuredClone(userSession);
    active.session.activeOrganizationId = "org_1";
    const response = await invoke(endpoints.listPlans, {}, context(active, { findOne }));
    expect(response.status).toBe(500);
    expect(await response.json()).toEqual({
      message: "Autumn secret key not found in ENV variables or passed into autumnHandler",
      code: "no_secret_key",
      statusCode: 500,
    });
    expect(findOne).toHaveBeenCalledOnce();
    expect(identify).not.toHaveBeenCalled();

    await expect(invoke(endpoints.getEntity, {}, context(active, { findOne })))
      .rejects.toThrow();
    expect(findOne).toHaveBeenCalledTimes(1);
  });

  test("missing and custom identities keep exact authorization behavior", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    const endpoints = autumn({ secretKey: "secret" }).endpoints;
    const missing = await invoke(endpoints.getEntity, { entityId: "entity_1" }, context(null));
    expect(missing.status).toBe(401);
    expect(await missing.json()).toEqual({
      message: "customerId returned from identify function is null",
      code: "no_customer_id",
      statusCode: 401,
    });
    const optional = await invokeServer(
      autumn({ secretKey: "secret" }),
      "getOrCreateCustomer",
      { errorOnNotFound: false },
    );
    expect(optional.status).toBe(200);
    expect(await optional.json()).toBeNull();
    expect(fetch).not.toHaveBeenCalled();

    const identityFailure = autumn({
      secretKey: "secret",
      identify: async () => { throw new Error("identity exploded"); },
    }).endpoints.listPlans;
    const failed = await invoke(identityFailure, {}, context(null));
    expect(failed.status).toBe(500);
    expect(await failed.json()).toEqual({
      message: "identity exploded",
      code: "internal_error",
      statusCode: 500,
    });
  });

  test("all routes use exact SDK paths, headers, identity injection, and transforms", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const { requests } = captureRequests();
    const plugin = autumn({
      secretKey: "secret",
      autumnURL: "https://autumn.example.test/preserved/base",
    });
    for (const [name, endpoint] of Object.entries(plugin.endpoints)) {
      const response = await invoke(endpoint, {
        ...validBodies[name],
        customerId: "spoofed",
        customerData: { customerId: "spoofed_nested" },
      });
      expect(response.status, name).toBe(422);
    }
    expect(requests).toHaveLength(15);
    for (const [index, name] of Object.keys(endpointPaths).entries()) {
      const request = requests[index];
      expect(request.method, name).toBe("POST");
      expect(request.url, name).toBe(
        `https://autumn.example.test/preserved/base${endpointPaths[name]}`,
      );
      expect(request.headers.authorization, name).toBe("Bearer secret");
      expect(request.headers.accept, name).toBe("application/json");
      expect(request.headers["content-type"], name).toBe("application/json");
      expect(request.headers["user-agent"], name).toBe(
        "speakeasy-sdk/typescript 0.10.18 2.882.0 2.3.0 @useautumn/sdk",
      );
      expect(request.headers["x-api-version"], name).toBe("2.3.0");
      expect(request.body, name).not.toHaveProperty("customerId");
      expect(request.body, name).not.toHaveProperty("customerData");
      if (name !== "listPlans") {
        expect(request.body.customer_id, name).toBe("user_1");
      }
    }
    expect(requests[10].body).toMatchObject({ start_cursor: "", limit: 50 });
    expect(requests[11].body).toMatchObject({ bin_size: "day" });
  });

  test("organization scopes and trusted identity data follow exact spread order", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const { requests } = captureRequests();
    const active = structuredClone(userSession);
    active.session.activeOrganizationId = "org_1";
    const adapter = {
      findOne: vi.fn(async () => ({ id: "org_1", name: "Organization" })),
    };
    const orgEndpoint = autumn({
      secretKey: "secret",
      customerScope: "organization",
    }).endpoints.getEntity;
    await invoke(orgEndpoint, { entityId: "entity_1" }, context(active, adapter));
    expect(requests[0].body.customer_id).toBe("org_1");

    const trusted = autumn({
      secretKey: "secret",
      identify: async () => ({
        customerId: "resolver_id",
        customerData: { customerId: "trusted_override", name: "Trusted" },
      }),
    }).endpoints.getOrCreateCustomer;
    await invoke(trusted, {}, context(null));
    expect(requests[1].body).toMatchObject({
      customer_id: "trusted_override",
      name: "Trusted",
      expand: ["balances.feature"],
    });
  });

  test("outbound schema failures occur after public validation and before fetch", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    const endpoint = autumn({ secretKey: "secret" }).endpoints.aggregateEvents;
    const response = await invoke(endpoint, { featureId: "feature_1", range: 123 });
    expect(response.status).toBe(500);
    const error = await response.json();
    expect(error).toMatchObject({ code: "internal_error", statusCode: 500 });
    expect(error.message).toMatch(/^Input validation failed: /);
    expect(error.message).toContain('"range"');
    expect(fetch).not.toHaveBeenCalled();
  });

  test("network errors preserve both default fail-open hooks and exact 555 errors", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("offline"); }));
    const plugin = autumn({
      secretKey: "secret",
      identify: async () => ({ customerId: "user_1" }),
    });
    const customer = await invokeServer(plugin, "getOrCreateCustomer", {});
    expect(customer.status).toBe(200);
    expect(await customer.json()).toEqual({
      message: "Response validation failed",
      code: "autumn_api_error",
      statusCode: 200,
    });
    const entity = await invokeServer(plugin, "getEntity", { entityId: "entity_1" });
    expect(entity.status).toBe(200);
    expect(await entity.json()).toEqual({
      id: null, name: null, customerId: null, featureId: null, createdAt: 0,
      env: "live", subscriptions: [], purchases: [], balances: {}, flags: {},
    });
    const attach = await invokeServer(plugin, "attach", { planId: "plan_1" });
    expect(attach.status).toBe(200);
    expect(await attach.json()).toEqual({
      message: 'API error occurred: Status 555 Content-Type "". Body: ""',
      code: "autumn_api_error",
      statusCode: 555,
    });
  });

  test("unexpected success and schema failures preserve their 2xx error envelopes", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    captureRequests(() => Response.json({}, { status: 201 }));
    const unexpected = await invokeServer(
      autumn({ secretKey: "secret" }),
      "listPlans",
      {},
    );
    expect(unexpected.status).toBe(200);
    const unexpectedError = await unexpected.json();
    expect(unexpectedError).toMatchObject({ code: "autumn_api_error", statusCode: 201 });
    expect(unexpectedError.message).toMatch(/^Unexpected Status or Content-Type/);

    captureRequests(() => Response.json({}, { status: 200 }));
    const invalid = await invokeServer(autumn({ secretKey: "secret" }), "listPlans", {});
    expect(invalid.status).toBe(200);
    const invalidError = await invalid.json();
    expect(invalidError).toMatchObject({ code: "autumn_api_error", statusCode: 200 });
    expect(invalidError.message).toMatch(/^Response validation failed/);
  });

  test("official React client uses literal Better Auth routes and credentials", async () => {
    const { requests } = captureRequests(() => new Response(null, { status: 204 }));
    const client = createAutumnClient({
      backendUrl: "https://auth.example.test",
      pathPrefix: "/api/auth/autumn",
      includeCredentials: true,
    });
    for (const name of Object.keys(endpointPaths)) {
      await client[name](validBodies[name]);
    }
    expect(requests.map(request => ({
      credentials: request.credentials,
      method: request.method,
      url: request.url,
    }))).toEqual(Object.keys(endpointPaths).map(name => ({
      credentials: "include",
      method: "POST",
      url: `https://auth.example.test/api/auth/autumn/${name}`,
    })));

    const literal = createAutumnClient({
      backendUrl: "https://auth.example.test/",
      pathPrefix: "/api/auth/autumn/",
      includeCredentials: false,
      headers: { "Content-Type": "text/plain", "x-custom": "yes" },
    });
    await literal.listPlans();
    expect(requests.at(-1)).toMatchObject({
      credentials: "same-origin",
      method: "POST",
      url: "https://auth.example.test//api/auth/autumn//listPlans",
    });
    expect(requests.at(-1).headers).toMatchObject({
      "content-type": "text/plain",
      "x-custom": "yes",
    });
    expect(requests.at(-1).body).toEqual({});
  });
});
