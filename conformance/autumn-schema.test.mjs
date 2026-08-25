import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

import * as sdk from "autumn-js";
import { routeConfigs } from "./node_modules/autumn-js/dist/better-auth/chunk-IIOL3QPN.mjs";
import { omitProtectedBodyFields } from "./node_modules/autumn-js/dist/better-auth/chunk-GJAMWZNZ.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const catalogPath = path.join(here, "..", "src", "autumn", "schema", "sdk-0.10.18.json");

const operations = [
  ["getOrCreateCustomer", "GetOrCreateCustomerParams$outboundSchema", "Customer$inboundSchema"],
  ["getEntity", "GetEntityParams$outboundSchema", "GetEntityResponse$inboundSchema"],
  ["attach", "AttachParams$outboundSchema", "AttachResponse$inboundSchema"],
  ["previewAttach", "PreviewAttachParams$outboundSchema", "PreviewAttachResponse$inboundSchema"],
  ["updateSubscription", "UpdateSubscriptionParams$outboundSchema", "BillingUpdateResponse$inboundSchema"],
  ["previewUpdateSubscription", "PreviewUpdateParams$outboundSchema", "PreviewUpdateResponse$inboundSchema"],
  ["openCustomerPortal", "OpenCustomerPortalParams$outboundSchema", "OpenCustomerPortalResponse$inboundSchema"],
  ["createReferralCode", "CreateReferralCodeParams$outboundSchema", "CreateReferralCodeResponse$inboundSchema"],
  ["redeemReferralCode", "RedeemReferralCodeParams$outboundSchema", "RedeemReferralCodeResponse$inboundSchema"],
  ["listPlans", "ListPlansParams$outboundSchema", "ListPlansResponse$inboundSchema"],
  ["listEvents", "EventsListParams$outboundSchema", "ListEventsResponse$inboundSchema"],
  ["aggregateEvents", "EventsAggregateParams$outboundSchema", "AggregateEventsResponse$inboundSchema"],
  ["multiAttach", "MultiAttachParams$outboundSchema", "MultiAttachResponse$inboundSchema"],
  ["previewMultiAttach", "PreviewMultiAttachParams$outboundSchema", "PreviewMultiAttachResponse$inboundSchema"],
  ["setupPayment", "SetupPaymentParams$outboundSchema", "SetupPaymentResponse$inboundSchema"],
];

function publicSchema(operation) {
  const route = routeConfigs.find(candidate => candidate.route === operation);
  return omitProtectedBodyFields({ schema: route.bodySchema });
}

describe("pinned Autumn Better Auth and SDK schema oracle", () => {
  test("pins every public, outbound, and inbound operation schema", async () => {
    const packageJson = JSON.parse(
      await readFile(path.join(here, "node_modules", "autumn-js", "package.json"), "utf8"),
    );
    const catalog = JSON.parse(await readFile(catalogPath, "utf8"));
    expect(packageJson.version).toBe("1.2.53");
    expect(catalog.generatedFrom).toBe("autumn-js@1.2.53 (@useautumn/sdk@0.10.18)");
    expect(new Set(routeConfigs.map(route => route.route))).toEqual(
      new Set(operations.map(([name]) => name)),
    );
    expect(Object.keys(catalog.roots)).toHaveLength(45);

    for (const [operation, outboundName, inboundName] of operations) {
      expect(publicSchema(operation)).toBeDefined();
      expect(sdk[outboundName]).toBeDefined();
      expect(sdk[inboundName]).toBeDefined();
      expect(catalog.roots).toHaveProperty(`public:${operation}`);
      expect(catalog.roots).toHaveProperty(`outbound:${operation}`);
      expect(catalog.roots).toHaveProperty(`inbound:${operation}`);
    }
  });

  test("public schemas omit protected identity, strip unknowns, and apply Better Call defaults", () => {
    expect(publicSchema("getOrCreateCustomer").parse({
      customerId: "attacker",
      metadata: { attacker: true },
      unknown: true,
    })).toEqual({ errorOnNotFound: true });

    expect(publicSchema("attach").parse({
      customerId: "attacker",
      planId: "pro",
      featureQuantities: [{ featureId: "seats", quantity: 2, unknown: true }],
      unknown: true,
    })).toEqual({
      planId: "pro",
      featureQuantities: [{ featureId: "seats", quantity: 2 }],
    });

    expect(publicSchema("multiAttach").parse({
      customerData: { name: "attacker" },
      plans: [{ planId: "pro" }],
    })).toEqual({ plans: [{ planId: "pro" }] });
  });

  test("public placeholders defer generated integer and enum validation to outbound schemas", () => {
    expect(publicSchema("listEvents").parse({ limit: 1.5 })).toEqual({ limit: 1.5 });
    expect(() => sdk["EventsListParams$outboundSchema"].parse({ limit: 1.5 })).toThrow();
    expect(publicSchema("aggregateEvents").parse({ featureId: "api", range: 123 })).toEqual({
      featureId: "api",
      range: 123,
    });
    expect(() => sdk["EventsAggregateParams$outboundSchema"].parse({
      featureId: "api",
      range: 123,
    })).toThrow();
  });

  test("outbound schemas remap recursively, preserve records, and materialize defaults", () => {
    expect(sdk["EventsListParams$outboundSchema"].parse({ customerId: "user_1" })).toEqual({
      start_cursor: "",
      limit: 50,
      customer_id: "user_1",
    });
    expect(sdk["EventsAggregateParams$outboundSchema"].parse({
      customerId: "user_1",
      featureId: ["api", "tokens"],
      filterBy: { model_name: "gpt" },
    })).toEqual({
      customer_id: "user_1",
      feature_id: ["api", "tokens"],
      bin_size: "day",
      filter_by: { model_name: "gpt" },
    });
  });

  test("inbound schemas project wire keys and reject the published invalid customer fail-open body", () => {
    const entity = {
      id: null,
      name: null,
      customer_id: null,
      feature_id: null,
      created_at: 0,
      env: "live",
      subscriptions: [],
      purchases: [],
      balances: {},
      flags: {},
      provider_only: true,
    };
    expect(sdk["GetEntityResponse$inboundSchema"].parse(entity)).toEqual({
      id: null,
      name: null,
      customerId: null,
      featureId: null,
      createdAt: 0,
      env: "live",
      subscriptions: [],
      purchases: [],
      balances: {},
      flags: {},
    });

    const customerFailOpen = {
      id: null,
      name: null,
      email: null,
      created_at: 0,
      fingerprint: null,
      stripe_id: null,
      env: "live",
      metadata: {},
      send_email_receipts: false,
      billing_controls: {},
      subscriptions: [],
      purchases: [],
      balances: {},
      flags: {},
    };
    expect(() => sdk["Customer$inboundSchema"].parse(customerFailOpen)).toThrow();
  });
});
