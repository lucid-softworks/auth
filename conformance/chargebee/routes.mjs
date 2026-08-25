import { chargebee } from "@chargebee/better-auth";
import { afterEach, describe, expect, test, vi } from "vitest";
import {
  callEndpoint,
  endpointContext,
  fakeAdapter,
  fakeChargebee,
  plans,
  responseBody,
  session,
} from "./helpers.mjs";

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

function install(options = {}) {
  const { client } = fakeChargebee(options.clientOverrides);
  const subscription = options.subscription ?? { enabled: true, plans };
  return {
    client,
    plugin: chargebee({ chargebeeClient: client, subscription, ...options.pluginOptions }),
  };
}

describe("@chargebee/better-auth@1.2.0 route/provider oracle", () => {
  test("creates a future checkout with JS seat/trial semantics and last-spread overrides", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-25T12:00:00.000Z"));
    const hostedOverrides = {
      customer: { id: "customer_override" },
      custom_checkout_field: "oracle",
    };
    const getHostedPageParams = vi.fn(async () => hostedOverrides);
    const { client, plugin } = install({
      clientOverrides: {
        customer: {
          list: vi.fn(async () => ({
            list: [{ customer: { id: "customer_existing", meta_data: { cohort: "old" } } }],
          })),
        },
      },
      subscription: { enabled: true, getHostedPageParams, plans },
    });
    const adapter = fakeAdapter({
      create: vi.fn(async ({ data }) => ({ id: "local_future", ...data })),
      findMany: vi.fn(async ({ model }) => model === "subscription" ? [] : []),
      findOne: vi.fn(async ({ model }) => model === "user" ? { id: "user_1" } : null),
      update: vi.fn(async ({ model, update }) => ({ id: `${model}_updated`, ...update })),
    });
    const context = endpointContext({ adapter });
    const request = new Request("https://auth.example.test/api/auth/subscription/create", {
      method: "POST",
    });
    const response = await callEndpoint(plugin.endpoints.createSubscription, {
      body: {
        cancelUrl: "/cancel",
        disableRedirect: true,
        itemPriceId: "price_pro",
        metadata: { ignoredWhenReusing: true },
        returnUrl: "/retained-but-unused",
        seats: 0,
        successUrl: "/success",
      },
      context,
      request,
    });
    expect(response.status).toBe(200);
    expect(await responseBody(response)).toEqual({
      id: "hosted_new",
      redirect: false,
      url: "https://chargebee.test/new",
    });
    expect(client.customer.list).toHaveBeenCalledWith({
      email: { is: "user@example.test" },
      limit: 1,
    });
    expect(client.customer.create).not.toHaveBeenCalled();
    expect(adapter.create).toHaveBeenCalledWith({
      data: {
        chargebeeCustomerId: "customer_existing",
        referenceId: "user_1",
        seats: 1,
        status: "future",
      },
      model: "subscription",
    });
    expect(getHostedPageParams).toHaveBeenCalledWith(
      {
        plan: plans[0],
        session: context.session.session,
        subscription: expect.objectContaining({ id: "local_future", seats: 1 }),
        user: context.session.user,
      },
      request,
      expect.any(Object),
    );
    expect(client.customer.update).toHaveBeenCalledWith("customer_existing", {
      meta_data: {
        pendingReferenceId: "user_1",
        pendingSubscriptionId: "local_future",
        userId: "user_1",
      },
    });
    expect(client.hostedPage.checkoutNewForItems).toHaveBeenCalledWith({
      cancel_url: "https://auth.example.test/api/auth/cancel",
      customer: { id: "customer_override" },
      custom_checkout_field: "oracle",
      redirect_url: "https://auth.example.test/api/auth/subscription/success?callbackURL=%2Fsuccess&subscriptionId=local_future",
      subscription: { trial_end: 1788264000 },
      subscription_items: [{ item_price_id: "price_pro", quantity: 1 }],
    });
    expect(JSON.stringify(client.hostedPage.checkoutNewForItems.mock.calls)).not.toMatch(
      /billingCycles|itemFamilyId|itemId|returnUrl|ignoredWhenReusing/,
    );
  });

  test("updates the requested owned active provider subscription with exact item mapping", async () => {
    const local = {
      chargebeeCustomerId: "customer_saved",
      chargebeeSubscriptionId: "provider_sub",
      id: "local_active",
      periodEnd: new Date("2027-01-01T00:00:00.000Z"),
      referenceId: "user_1",
      seats: 1,
      status: "active",
    };
    const provider = {
      id: "provider_sub",
      status: "active",
      subscription_items: [{ item_price_id: "price_old", quantity: 1 }],
    };
    const { client, plugin } = install({
      clientOverrides: {
        subscription: { list: vi.fn(async () => ({ list: [{ subscription: provider }] })) },
      },
    });
    const adapter = fakeAdapter({ findOne: vi.fn(async () => local) });
    const response = await callEndpoint(plugin.endpoints.updateSubscription, {
      body: {
        cancelUrl: "https://app.example.test/cancel",
        itemPriceId: ["price_pro", "price_addon"],
        seats: 3,
        subscriptionId: "provider_sub",
        successUrl: "https://app.example.test/success",
      },
      context: endpointContext({ adapter }),
    });
    expect(response.status).toBe(200);
    expect(await responseBody(response)).toEqual({
      id: "hosted_existing",
      redirect: true,
      url: "https://chargebee.test/existing",
    });
    expect(client.subscription.list).toHaveBeenCalledWith({
      customer_id: { is: "customer_saved" },
      limit: 100,
    });
    expect(client.hostedPage.checkoutExistingForItems).toHaveBeenCalledWith({
      cancel_url: "https://app.example.test/cancel",
      redirect_url: "https://auth.example.test/api/auth/subscription/success?callbackURL=https%3A%2F%2Fapp.example.test%2Fsuccess&subscriptionId=local_active",
      subscription: { id: "provider_sub" },
      subscription_items: [
        { item_price_id: "price_pro", quantity: 3 },
        { item_price_id: "price_addon", quantity: 3 },
      ],
    });
  });

  test("lists only exact active statuses and enriches from plan-first local items", async () => {
    const subscriptions = [
      { id: "sub_active", referenceId: "user_1", status: "active" },
      { id: "sub_trial", referenceId: "user_1", status: "in_trial" },
      { id: "sub_nonrenew", referenceId: "user_1", status: "non_renewing" },
      { id: "sub_paused", referenceId: "user_1", status: "paused" },
    ];
    const adapter = fakeAdapter({
      findMany: vi.fn(async ({ model, where }) => {
        if (model === "subscription") return subscriptions;
        const id = where[0].value;
        return [
          { itemPriceId: "price_addon", itemType: "addon", subscriptionId: id },
          { itemPriceId: "price_pro", itemType: "plan", subscriptionId: id },
        ];
      }),
    });
    const { plugin } = install();
    const response = await callEndpoint(plugin.endpoints.listActiveSubscriptions, {
      context: endpointContext({ adapter }),
      query: {},
    });
    expect(response.status).toBe(200);
    expect(await responseBody(response)).toEqual(subscriptions.slice(0, 3).map(subscription => ({
      ...subscription,
      itemPriceId: "price_pro",
      limits: { projects: 12 },
    })));
  });

  test("portal and cancel open Chargebee portal with distinct exact redirect URLs", async () => {
    const local = {
      chargebeeCustomerId: "customer_saved",
      chargebeeSubscriptionId: "provider_sub",
      id: "local_active",
      referenceId: "user_1",
      status: "non_renewing",
    };
    const { client, plugin } = install({
      clientOverrides: {
        subscription: {
          list: vi.fn(async () => ({
            list: [{ subscription: { id: "provider_sub", status: "non_renewing" } }],
          })),
        },
      },
    });
    const adapter = fakeAdapter({ findMany: vi.fn(async () => [local]) });
    const context = endpointContext({
      adapter,
      session: session({ user: { chargebeeCustomerId: "customer_saved" } }),
    });
    for (const [endpoint, body] of [
      [plugin.endpoints.createPortalSession, { returnUrl: "/account" }],
      [plugin.endpoints.cancelSubscription, { returnUrl: "/billing" }],
    ]) {
      const response = await callEndpoint(endpoint, { body, context });
      expect(response.status).toBe(200);
      expect(await responseBody(response)).toEqual({
        redirect: true,
        url: "https://chargebee.test/portal",
      });
    }
    expect(client.portalSession.create.mock.calls).toEqual([
      [{
        customer: { id: "customer_saved" },
        redirect_url: "https://auth.example.test/api/auth/account",
      }],
      [{
        customer: { id: "customer_saved" },
        redirect_url: "https://auth.example.test/api/auth/subscription/cancel/callback?callbackURL=%2Fbilling&subscriptionId=local_active",
      }],
    ]);
    expect(client.subscription.cancel).not.toHaveBeenCalled();
  });

  test("pins validation aggregation and absent-subscription runtime failure", async () => {
    const enabled = install().plugin;
    await expect(callEndpoint(enabled.endpoints.createSubscription, { body: {} })).rejects.toMatchObject({
      message: "[body.itemPriceId] Invalid input; [body.successUrl] Invalid input: expected string, received undefined; [body.cancelUrl] Invalid input: expected string, received undefined",
      status: 400,
    });

    const { client } = fakeChargebee();
    const absent = chargebee({ chargebeeClient: client });
    await expect(
      callEndpoint(absent.endpoints.createSubscription, {
        body: { cancelUrl: "/cancel", itemPriceId: "price_pro", successUrl: "/success" },
      }),
    ).rejects.toThrow(
      "Cannot read properties of undefined (reading 'getHostedPageParams')",
    );
  });
});
