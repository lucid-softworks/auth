import { chargebee } from "@chargebee/better-auth";
import { describe, expect, test } from "vitest";
import { fakeChargebee, plans } from "./helpers.mjs";

const endpoints = {
  chargebeeWebhook: ["POST", "/chargebee/webhook", 1, false],
  createSubscription: ["POST", "/subscription/create", 4, undefined],
  updateSubscription: ["POST", "/subscription/update", 4, undefined],
  subscriptionSuccess: ["GET", "/subscription/success", 2, false],
  cancelSubscription: ["POST", "/subscription/cancel", 4, undefined],
  cancelSubscriptionCallback: ["GET", "/subscription/cancel/callback", 2, undefined],
  createPortalSession: ["POST", "/subscription/portal", 4, undefined],
  listActiveSubscriptions: ["GET", "/subscription/list", 3, undefined],
};

function install(options = {}) {
  const { client } = fakeChargebee();
  return { client, plugin: chargebee({ chargebeeClient: client, ...options }) };
}

describe("@chargebee/better-auth@1.2.0 composition oracle", () => {
  test("pins server identity, endpoint order, schemas, metadata, and middleware nesting", () => {
    const { client, plugin } = install({ subscription: { enabled: true, plans } });
    expect(plugin.id).toBe("chargebee");
    expect(client.__clientIdentifier).toHaveBeenCalledOnce();
    expect(client.__clientIdentifier).toHaveBeenCalledWith("better-auth 1.2.0");
    expect(Object.keys(plugin.endpoints)).toEqual(Object.keys(endpoints));
    for (const [name, [method, path, middlewareCount, isAction]] of Object.entries(endpoints)) {
      const endpoint = plugin.endpoints[name];
      expect({
        isAction: endpoint.options.metadata?.isAction,
        method: endpoint.options.method,
        middlewareCount: endpoint.options.use?.length,
        nestedMiddleware: endpoint.options.use?.map(value => value.options?.use?.length),
        path: endpoint.path,
      }).toEqual({
        isAction,
        method,
        middlewareCount,
        nestedMiddleware: middlewareCount === 4
          ? [3, 2, 2, undefined]
          : middlewareCount === 3
            ? [3, 2, undefined]
            : middlewareCount === 2
              ? [2, undefined]
              : [undefined],
        path,
      });
    }
  });

  test("always installs eight routes while only schema contributions are conditional", () => {
    const absent = install().plugin;
    const disabled = install({ subscription: { enabled: false, plans } }).plugin;
    const enabled = install({ subscription: { enabled: true, plans } }).plugin;
    const organization = install({
      organization: { enabled: true },
      subscription: { enabled: true, plans },
    }).plugin;
    for (const plugin of [absent, disabled, enabled, organization]) {
      expect(Object.keys(plugin.endpoints)).toEqual(Object.keys(endpoints));
    }
    expect(absent.schema).toEqual({
      user: { fields: { chargebeeCustomerId: { required: false, type: "string", unique: true } } },
    });
    expect(disabled.schema).toEqual(absent.schema);
    expect(Object.keys(enabled.schema)).toEqual(["user", "subscription", "subscriptionItem"]);
    expect(Object.keys(organization.schema)).toEqual([
      "subscription",
      "subscriptionItem",
      "organization",
    ]);
    expect(organization.schema).not.toHaveProperty("user");
  });

  test("pins every persistence field, cascade, default, and non-unique reference", () => {
    const schema = install({ subscription: { enabled: true, plans } }).plugin.schema;
    expect(schema.subscription.fields).toEqual({
      canceledAt: { required: false, type: "date" },
      chargebeeCustomerId: { required: false, type: "string" },
      chargebeeSubscriptionId: { required: false, type: "string", unique: true },
      metadata: { required: false, type: "string" },
      periodEnd: { required: false, type: "date" },
      periodStart: { required: false, type: "date" },
      referenceId: { required: true, type: "string" },
      seats: { required: false, type: "number" },
      status: { defaultValue: "future", required: false, type: "string" },
      trialEnd: { required: false, type: "date" },
      trialStart: { required: false, type: "date" },
    });
    expect(schema.subscriptionItem.fields).toEqual({
      amount: { required: false, type: "number" },
      itemPriceId: { required: true, type: "string" },
      itemType: { required: true, type: "string" },
      quantity: { required: true, type: "number" },
      subscriptionId: {
        references: { field: "id", model: "subscription", onDelete: "cascade" },
        required: true,
        type: "string",
      },
      unitPrice: { required: false, type: "number" },
    });
    expect(schema.subscription.fields.referenceId.unique).toBeUndefined();
  });

  test("pins exact body/query schema order and callback casing", () => {
    const plugin = install({ subscription: { enabled: true, plans } }).plugin;
    expect(Object.keys(plugin.endpoints.createSubscription.options.body.shape)).toEqual([
      "itemPriceId", "successUrl", "cancelUrl", "returnUrl", "referenceId",
      "customerType", "seats", "metadata", "disableRedirect", "trialEnd",
    ]);
    expect(Object.keys(plugin.endpoints.updateSubscription.options.body.shape)).toEqual([
      "itemPriceId", "successUrl", "cancelUrl", "returnUrl", "referenceId",
      "subscriptionId", "customerType", "seats", "metadata", "disableRedirect",
    ]);
    for (const endpoint of [
      plugin.endpoints.subscriptionSuccess,
      plugin.endpoints.cancelSubscriptionCallback,
    ]) {
      const schema = endpoint.options.query;
      expect(Object.keys(schema.shape)).toEqual(["callbackURL", "subscriptionId"]);
      expect(schema.parse({ callbackURL: "/ok", callbackUrl: "/wrong" })).toEqual({
        callbackURL: "/ok",
      });
    }
  });
});
