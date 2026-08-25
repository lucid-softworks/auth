import { stripe } from "@better-auth/stripe";
import {
  STRIPE_ERROR_CODES,
  stripeClient,
} from "@better-auth/stripe/client";
import { readFile } from "node:fs/promises";
import { createAuthClient } from "better-auth/client";
import { describe, expect, test, vi } from "vitest";

const ENDPOINTS = {
  stripeWebhook: {
    method: "POST",
    middlewareCount: 0,
    operationId: "handleStripeWebhook",
    path: "/stripe/webhook",
  },
  upgradeSubscription: {
    method: "POST",
    middlewareCount: 3,
    operationId: "upgradeSubscription",
    path: "/subscription/upgrade",
  },
  cancelSubscription: {
    method: "POST",
    middlewareCount: 3,
    operationId: "cancelSubscription",
    path: "/subscription/cancel",
  },
  restoreSubscription: {
    method: "POST",
    middlewareCount: 2,
    operationId: "restoreSubscription",
    path: "/subscription/restore",
  },
  listActiveSubscriptions: {
    method: "GET",
    middlewareCount: 2,
    operationId: "listActiveSubscriptions",
    path: "/subscription/list",
  },
  subscriptionSuccess: {
    method: "GET",
    middlewareCount: 1,
    operationId: "handleSubscriptionSuccess",
    path: "/subscription/success",
  },
  createBillingPortal: {
    method: "POST",
    middlewareCount: 3,
    operationId: "createBillingPortal",
    path: "/subscription/billing-portal",
  },
};

const ERRORS = {
  UNAUTHORIZED: "Unauthorized access",
  INVALID_REQUEST_BODY: "Invalid request body",
  SUBSCRIPTION_NOT_FOUND: "Subscription not found",
  SUBSCRIPTION_PLAN_NOT_FOUND: "Subscription plan not found",
  ALREADY_SUBSCRIBED_PLAN: "You're already subscribed to this plan",
  REFERENCE_ID_NOT_ALLOWED: "Reference id is not allowed",
  CUSTOMER_NOT_FOUND: "Stripe customer not found for this user",
  UNABLE_TO_CREATE_CUSTOMER: "Unable to create customer",
  UNABLE_TO_CREATE_BILLING_PORTAL: "Unable to create billing portal session",
  STRIPE_SIGNATURE_NOT_FOUND: "Stripe signature not found",
  STRIPE_WEBHOOK_SECRET_NOT_FOUND: "Stripe webhook secret not found",
  STRIPE_WEBHOOK_ERROR: "Stripe webhook error",
  FAILED_TO_CONSTRUCT_STRIPE_EVENT: "Failed to construct Stripe event",
  FAILED_TO_FETCH_PLANS: "Failed to fetch plans",
  EMAIL_VERIFICATION_REQUIRED:
    "Email verification is required before you can subscribe to a plan",
  SUBSCRIPTION_NOT_ACTIVE: "Subscription is not active",
  SUBSCRIPTION_NOT_SCHEDULED_FOR_CANCELLATION:
    "Subscription is not scheduled for cancellation",
  SUBSCRIPTION_NOT_PENDING_CHANGE:
    "Subscription has no pending cancellation or scheduled plan change",
  ORGANIZATION_NOT_FOUND: "Organization not found",
  ORGANIZATION_SUBSCRIPTION_NOT_ENABLED:
    "Organization subscription is not enabled",
  AUTHORIZE_REFERENCE_REQUIRED:
    "Organization subscriptions require authorizeReference callback to be configured",
  ORGANIZATION_HAS_ACTIVE_SUBSCRIPTION:
    "Cannot delete organization with active subscription",
  ORGANIZATION_REFERENCE_ID_REQUIRED:
    "Reference ID is required. Provide referenceId or set activeOrganizationId in session",
};

function fakeStripeClient(overrides = {}) {
  return {
    billingPortal: { sessions: { create: vi.fn() } },
    checkout: { sessions: { create: vi.fn(), retrieve: vi.fn() } },
    customers: {
      create: vi.fn(),
      list: vi.fn(),
      retrieve: vi.fn(),
      search: vi.fn(),
      update: vi.fn(),
    },
    prices: { list: vi.fn(), retrieve: vi.fn() },
    subscriptions: { list: vi.fn(), retrieve: vi.fn(), update: vi.fn() },
    subscriptionSchedules: {
      create: vi.fn(),
      release: vi.fn(),
      retrieve: vi.fn(),
      update: vi.fn(),
    },
    webhooks: { constructEvent: vi.fn() },
    ...overrides,
  };
}

function install(overrides = {}) {
  const options = {
    stripeClient: fakeStripeClient(),
    stripeWebhookSecret: "whsec_oracle",
    ...overrides,
  };
  return { options, plugin: stripe(options) };
}

function normalizeSchema(schema) {
  return Object.fromEntries(
    Object.entries(schema).map(([model, definition]) => [
      model,
      {
        ...(definition.modelName ? { modelName: definition.modelName } : {}),
        fields: Object.fromEntries(
          Object.entries(definition.fields).map(([field, config]) => [
            field,
            {
              type: config.type,
              ...(config.required === undefined
                ? {}
                : { required: config.required }),
              ...(config.defaultValue === undefined
                ? {}
                : { defaultValue: config.defaultValue }),
              ...(config.fieldName ? { fieldName: config.fieldName } : {}),
            },
          ]),
        ),
      },
    ]),
  );
}

function webhookRequest({ body, signature } = {}) {
  return new Request("https://auth.example.test/api/auth/stripe/webhook", {
    method: "POST",
    ...(signature ? { headers: { "stripe-signature": signature } } : {}),
    ...(body === undefined ? {} : { body }),
  });
}

async function callWebhook(endpoint, request) {
  return endpoint({
    asResponse: true,
    context: {
      logger: { error: vi.fn(), info: vi.fn(), warn: vi.fn() },
    },
    request,
  });
}

function successContext(session) {
  return {
    isTrustedOrigin: () => true,
    logger: { error: vi.fn(), info: vi.fn(), warn: vi.fn() },
    options: { baseURL: "https://auth.example.test/api/auth" },
    ...(session === undefined ? {} : { session }),
  };
}

async function callSuccess(endpoint, query, session) {
  return endpoint({
    asResponse: true,
    context: successContext(session),
    headers: new Headers(),
    query,
    request: new Request(
      "https://auth.example.test/api/auth/subscription/success",
    ),
  });
}

describe("@better-auth/stripe@1.7.1 oracle", () => {
  test("pins the published plugin and oracle SDK versions", async () => {
    const pluginPackage = JSON.parse(
      await readFile(
        new URL("node_modules/@better-auth/stripe/package.json", import.meta.url),
        "utf8",
      ),
    );
    const sdkPackage = JSON.parse(
      await readFile(
        new URL("node_modules/stripe/package.json", import.meta.url),
        "utf8",
      ),
    );

    expect(pluginPackage.version).toBe("1.7.1");
    expect(pluginPackage.peerDependencies.stripe).toBe(
      "^18 || ^19 || ^20 || ^21 || ^22",
    );
    expect(sdkPackage.version).toBe("22.0.1");
  });

  test("snapshots server and client metadata", () => {
    const { options, plugin } = install();
    const client = stripeClient({ subscription: true });

    expect(Object.keys(plugin)).toEqual([
      "id",
      "version",
      "endpoints",
      "init",
      "schema",
      "options",
      "$ERROR_CODES",
    ]);
    expect(plugin).toMatchObject({ id: "stripe", version: "1.7.1" });
    expect(plugin.options).toBe(options);
    expect(client).toMatchObject({
      id: "stripe-client",
      pathMethods: {
        "/subscription/billing-portal": "POST",
        "/subscription/restore": "POST",
      },
      version: "1.7.1",
    });
    expect(Object.keys(client)).toEqual([
      "id",
      "version",
      "$InferServerPlugin",
      "pathMethods",
      "$ERROR_CODES",
    ]);
    expect(stripeClient()).toEqual(client);
  });

  test("shares the complete exact error dictionary", () => {
    const { plugin } = install();
    const serverErrors = Object.fromEntries(
      Object.entries(plugin.$ERROR_CODES).map(([name, error]) => [
        name,
        error.message,
      ]),
    );

    expect(serverErrors).toEqual(ERRORS);
    expect(plugin.$ERROR_CODES).toBe(STRIPE_ERROR_CODES);
    expect(stripeClient({ subscription: true }).$ERROR_CODES).toBe(
      STRIPE_ERROR_CODES,
    );
    for (const [name, error] of Object.entries(STRIPE_ERROR_CODES)) {
      expect(error).toMatchObject({ code: name, message: ERRORS[name] });
      expect(error.toString()).toBe(name);
    }
  });

  test("registers the hidden webhook always and subscriptions conditionally", () => {
    const disabled = install().plugin;
    const enabled = install({ subscription: { enabled: true, plans: [] } })
      .plugin;

    expect(Object.keys(disabled.endpoints)).toEqual(["stripeWebhook"]);
    expect(Object.keys(enabled.endpoints)).toEqual(Object.keys(ENDPOINTS));

    for (const [name, expected] of Object.entries(ENDPOINTS)) {
      const endpoint = enabled.endpoints[name];
      expect({
        method: endpoint.options.method,
        middlewareCount: endpoint.options.use.length - 1,
        operationId: endpoint.options.metadata.openapi.operationId,
        path: endpoint.path,
      }).toEqual(expected);
    }

    const webhook = enabled.endpoints.stripeWebhook.options;
    expect(webhook).toMatchObject({
      cloneRequest: true,
      disableBody: true,
      metadata: {
        openapi: { operationId: "handleStripeWebhook" },
        scope: "server",
      },
    });
    expect(webhook).not.toHaveProperty("body");
    expect(enabled.endpoints.subscriptionSuccess.options.metadata).not.toHaveProperty(
      "scope",
    );
  });

  test("pins request defaults, validation, stripping, and exact success keys", () => {
    const endpoints = install({ subscription: { enabled: true, plans: [] } })
      .plugin.endpoints;
    const upgrade = endpoints.upgradeSubscription.options.body;
    const cancel = endpoints.cancelSubscription.options.body;
    const restore = endpoints.restoreSubscription.options.body;
    const list = endpoints.listActiveSubscriptions.options.query;
    const success = endpoints.subscriptionSuccess.options.query;
    const portal = endpoints.createBillingPortal.options.body;

    expect(upgrade.parse({ plan: "Pro", seats: -2, locale: "", extra: true }))
      .toEqual({
        plan: "Pro",
        seats: -2,
        locale: "",
        successUrl: "/",
        cancelUrl: "/",
        scheduleAtPeriodEnd: false,
        disableRedirect: false,
      });
    expect(upgrade.safeParse({}).success).toBe(false);
    expect(upgrade.safeParse({ plan: "pro", customerType: "team" }).success)
      .toBe(false);
    expect(upgrade.safeParse({ plan: "pro", locale: 1 }).success).toBe(false);

    expect(cancel.parse({ returnUrl: "/return", extra: true })).toEqual({
      returnUrl: "/return",
      disableRedirect: false,
    });
    expect(cancel.safeParse({}).success).toBe(false);
    expect(restore.parse({ extra: true })).toEqual({});
    expect(list.parse(undefined)).toBeUndefined();
    expect(list.parse({ referenceId: "ref", extra: true })).toEqual({
      referenceId: "ref",
    });
    expect(portal.parse({ extra: true })).toEqual({
      returnUrl: "/",
      disableRedirect: false,
    });

    expect(
      success.parse({
        callbackURL: "/correct",
        callbackUrl: "/wrong",
        callback_url: "/also-wrong",
        checkoutSessionId: "cs_123",
        arbitrary: { nested: true },
      }),
    ).toEqual({
      callbackURL: "/correct",
      callbackUrl: "/wrong",
      callback_url: "/also-wrong",
      checkoutSessionId: "cs_123",
      arbitrary: { nested: true },
    });
  });

  test("pins conditional schema and ignores disabled subscription remapping", () => {
    const remap = {
      organization: {
        modelName: "teams",
        fields: { stripeCustomerId: "stripe_org_customer" },
      },
      subscription: {
        modelName: "memberships",
        fields: { plan: "tier", referenceId: "owner" },
      },
      user: {
        modelName: "accounts",
        fields: { stripeCustomerId: "stripe_user_customer" },
      },
    };
    const disabled = normalizeSchema(
      install({ organization: { enabled: true }, schema: remap }).plugin.schema,
    );
    expect(disabled).toEqual({
      user: {
        modelName: "accounts",
        fields: {
          stripeCustomerId: {
            type: "string",
            required: false,
            fieldName: "stripe_user_customer",
          },
        },
      },
      organization: {
        modelName: "teams",
        fields: {
          stripeCustomerId: {
            type: "string",
            required: false,
            fieldName: "stripe_org_customer",
          },
        },
      },
    });

    const enabled = normalizeSchema(
      install({
        organization: { enabled: true },
        schema: remap,
        subscription: { enabled: true, plans: [] },
      }).plugin.schema,
    );
    expect(Object.keys(enabled)).toEqual([
      "subscription",
      "user",
      "organization",
    ]);
    expect(enabled.subscription.modelName).toBe("memberships");
    expect(enabled.subscription.fields.plan).toEqual({
      type: "string",
      required: true,
      fieldName: "tier",
    });
    expect(enabled.subscription.fields.referenceId).toEqual({
      type: "string",
      required: true,
      fieldName: "owner",
    });
    expect(enabled.subscription.fields.status).toEqual({
      type: "string",
      defaultValue: "incomplete",
    });
    expect(enabled.subscription.fields.cancelAtPeriodEnd).toEqual({
      type: "boolean",
      required: false,
      defaultValue: false,
    });
    expect(Object.keys(enabled.subscription.fields)).toEqual([
      "plan",
      "referenceId",
      "stripeCustomerId",
      "stripeSubscriptionId",
      "status",
      "periodStart",
      "periodEnd",
      "trialStart",
      "trialEnd",
      "cancelAtPeriodEnd",
      "cancelAt",
      "canceledAt",
      "endedAt",
      "seats",
      "billingInterval",
      "stripeScheduleId",
    ]);
  });

  test("infers all six client actions with exact methods and paths", async () => {
    const requests = [];
    const client = createAuthClient({
      baseURL: "https://auth.example.test",
      fetchOptions: {
        customFetchImpl: async (input, init = {}) => {
          requests.push({
            body: init.body,
            method: init.method,
            url: String(input),
          });
          return Response.json({ success: true });
        },
      },
      plugins: [stripeClient({ subscription: true })],
    });

    await client.subscription.upgrade({ plan: "pro" });
    await client.subscription.cancel({ returnUrl: "/return" });
    await client.subscription.restore({});
    await client.subscription.list({ query: { referenceId: "ref" } });
    await client.subscription.success({
      query: { callbackURL: "/done", checkoutSessionId: "cs_123" },
    });
    await client.subscription.billingPortal({});

    expect(requests).toEqual([
      {
        body: '{"plan":"pro"}',
        method: "POST",
        url: "https://auth.example.test/api/auth/subscription/upgrade",
      },
      {
        body: '{"returnUrl":"/return"}',
        method: "POST",
        url: "https://auth.example.test/api/auth/subscription/cancel",
      },
      {
        body: "{}",
        method: "POST",
        url: "https://auth.example.test/api/auth/subscription/restore",
      },
      {
        body: null,
        method: "GET",
        url: "https://auth.example.test/api/auth/subscription/list?referenceId=ref",
      },
      {
        body: null,
        method: "GET",
        url: "https://auth.example.test/api/auth/subscription/success?callbackURL=%2Fdone&checkoutSessionId=cs_123",
      },
      {
        body: "{}",
        method: "POST",
        url: "https://auth.example.test/api/auth/subscription/billing-portal",
      },
    ]);
  });

  test("returns exact webhook validation errors before verification", async () => {
    const missingBody = install().plugin.endpoints.stripeWebhook;
    expect(await (await callWebhook(missingBody, webhookRequest())).json())
      .toEqual({ message: ERRORS.INVALID_REQUEST_BODY, code: "INVALID_REQUEST_BODY" });

    expect(
      await (
        await callWebhook(missingBody, webhookRequest({ body: "payload" }))
      ).json(),
    ).toEqual({
      message: ERRORS.STRIPE_SIGNATURE_NOT_FOUND,
      code: "STRIPE_SIGNATURE_NOT_FOUND",
    });

    const missingSecret = install({ stripeWebhookSecret: "" }).plugin.endpoints
      .stripeWebhook;
    const secretResponse = await callWebhook(
      missingSecret,
      webhookRequest({ body: "payload", signature: "sig" }),
    );
    expect(secretResponse.status).toBe(500);
    expect(await secretResponse.json()).toEqual({
      message: ERRORS.STRIPE_WEBHOOK_SECRET_NOT_FOUND,
      code: "STRIPE_WEBHOOK_SECRET_NOT_FOUND",
    });
  });

  test("prefers async webhook verification and forwards every event", async () => {
    const event = { id: "evt_123", type: "custom.event" };
    const constructEvent = vi.fn();
    const constructEventAsync = vi.fn(async () => event);
    const onEvent = vi.fn(async () => {});
    const stripeClient = fakeStripeClient({
      webhooks: { constructEvent, constructEventAsync },
    });
    const endpoint = install({ onEvent, stripeClient }).plugin.endpoints
      .stripeWebhook;

    const response = await callWebhook(
      endpoint,
      webhookRequest({ body: "payload", signature: "sig" }),
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ success: true });
    expect(constructEventAsync).toHaveBeenCalledWith(
      "payload",
      "sig",
      "whsec_oracle",
    );
    expect(constructEvent).not.toHaveBeenCalled();
    expect(onEvent).toHaveBeenCalledWith(event);
  });

  test("falls back to sync verification and maps construction failures", async () => {
    const event = { id: "evt_sync", type: "unknown.event" };
    const constructEvent = vi.fn(() => event);
    const endpoint = install({
      stripeClient: fakeStripeClient({ webhooks: { constructEvent } }),
    }).plugin.endpoints.stripeWebhook;
    const response = await callWebhook(
      endpoint,
      webhookRequest({ body: "payload", signature: "sig" }),
    );
    expect(response.status).toBe(200);
    expect(constructEvent).toHaveBeenCalledWith(
      "payload",
      "sig",
      "whsec_oracle",
    );

    const failing = install({
      stripeClient: fakeStripeClient({
        webhooks: {
          constructEventAsync: vi.fn(async () => {
            throw new Error("bad signature");
          }),
        },
      }),
    }).plugin.endpoints.stripeWebhook;
    const failedResponse = await callWebhook(
      failing,
      webhookRequest({ body: "payload", signature: "sig" }),
    );
    expect(failedResponse.status).toBe(400);
    expect(await failedResponse.json()).toEqual({
      message: ERRORS.FAILED_TO_CONSTRUCT_STRIPE_EVENT,
      code: "FAILED_TO_CONSTRUCT_STRIPE_EVENT",
    });
  });

  test("maps event-handler failures after valid webhook verification", async () => {
    const endpoint = install({
      onEvent: vi.fn(async () => {
        throw new Error("handler failed");
      }),
      stripeClient: fakeStripeClient({
        webhooks: {
          constructEventAsync: vi.fn(async () => ({ type: "custom.event" })),
        },
      }),
    }).plugin.endpoints.stripeWebhook;
    const response = await callWebhook(
      endpoint,
      webhookRequest({ body: "payload", signature: "sig" }),
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      message: ERRORS.STRIPE_WEBHOOK_ERROR,
      code: "STRIPE_WEBHOOK_ERROR",
    });
  });

  test("preserves success redirect ordering and exact callbackURL casing", async () => {
    const retrieve = vi.fn(async () => {
      throw new Error("provider unavailable");
    });
    const endpoint = install({
      stripeClient: fakeStripeClient({
        checkout: { sessions: { create: vi.fn(), retrieve } },
      }),
      subscription: { enabled: true, plans: [] },
    }).plugin.endpoints.subscriptionSuccess;

    const noSession = await callSuccess(endpoint, {
      callbackURL: "/done/{CHECKOUT_SESSION_ID}",
      checkoutSessionId: "cs_no_session",
    });
    expect(noSession.headers.get("location")).toBe(
      "https://auth.example.test/api/auth/done/{CHECKOUT_SESSION_ID}",
    );
    expect(retrieve).not.toHaveBeenCalled();

    const session = { session: { id: "session" }, user: { id: "user" } };
    const noCheckout = await callSuccess(
      endpoint,
      { callbackURL: "/done/{CHECKOUT_SESSION_ID}" },
      session,
    );
    expect(noCheckout.headers.get("location")).toBe(
      "https://auth.example.test/api/auth/done/{CHECKOUT_SESSION_ID}",
    );
    expect(retrieve).not.toHaveBeenCalled();

    const providerFailure = await callSuccess(
      endpoint,
      {
        callbackURL: "/done/{CHECKOUT_SESSION_ID}/{CHECKOUT_SESSION_ID}",
        checkoutSessionId: "cs_exact",
      },
      session,
    );
    expect(providerFailure.headers.get("location")).toBe(
      "https://auth.example.test/api/auth/done/cs_exact/cs_exact",
    );
    expect(retrieve).toHaveBeenCalledWith("cs_exact");

    const wrongCase = await callSuccess(
      endpoint,
      { callbackUrl: "/wrong", checkoutSessionId: "cs_wrong" },
      session,
    );
    expect(wrongCase.headers.get("location")).toBe(
      "https://auth.example.test/api/auth/",
    );
  });

  test("pins initialization warnings for missing organization composition and seats", () => {
    const missingOrganizationLogger = {
      error: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
    };
    const missingOrganization = install({ organization: { enabled: true } })
      .plugin;
    expect(
      missingOrganization.init({
        getPlugin: () => undefined,
        logger: missingOrganizationLogger,
      }),
    ).toBeUndefined();
    expect(missingOrganizationLogger.error).toHaveBeenCalledWith(
      "Organization plugin not found",
    );

    const seatLogger = { error: vi.fn(), info: vi.fn(), warn: vi.fn() };
    install({
      subscription: {
        enabled: true,
        plans: [{ name: "team", priceId: "price_base", seatPriceId: "seat" }],
      },
    }).plugin.init({ logger: seatLogger });
    expect(seatLogger.error).toHaveBeenCalledWith(
      "seatPriceId is configured on a plan but stripe organization option is not enabled. Seat-based billing requires `organization: { enabled: true }` in stripe plugin options.",
    );
  });
});
