import {
  CHARGEBEE_ERROR_CODES,
  chargebee,
  createChargebeeWebhookProcessor,
} from "@chargebee/better-auth";
import * as clientExports from "@chargebee/better-auth/client";
import * as rootExports from "@chargebee/better-auth";
import { describe, expect, test } from "vitest";
import { fakeChargebee, packageJson, packageLock, packageText } from "./helpers.mjs";

const errors = {
  ACTIVE_SUBSCRIPTION_EXISTS: "An active subscription already exists",
  ALREADY_SUBSCRIBED: "You're already subscribed to this plan",
  AUTHORIZE_REFERENCE_REQUIRED: "Organization subscriptions require authorizeReference callback to be configured",
  CUSTOMER_NOT_FOUND: "Chargebee customer not found for this user",
  EMAIL_VERIFICATION_REQUIRED: "Email verification is required before you can subscribe to a plan",
  ORGANIZATION_NOT_FOUND: "Organization not found",
  ORGANIZATION_REFERENCE_ID_REQUIRED: "Reference ID is required. Provide referenceId or set activeOrganizationId in session",
  ORGANIZATION_SUBSCRIPTION_NOT_ENABLED: "Organization subscription is not enabled",
  ORG_HAS_ACTIVE_SUBSCRIPTIONS: "Cannot delete organization with active subscriptions",
  PLAN_NOT_FOUND: "Plan not found",
  SUBSCRIPTION_NOT_FOUND: "Subscription not found",
  UNABLE_TO_CREATE_CUSTOMER: "Unable to create Chargebee customer",
  UNAUTHORIZED_REFERENCE: "Unauthorized access to this reference",
  WEBHOOK_VERIFICATION_FAILED: "Webhook verification failed",
};

describe("@chargebee/better-auth@1.2.0 immutable artifact oracle", () => {
  test("pins package versions, registry integrity, hashes, engines, and exports", async () => {
    const pkg = await packageJson("@chargebee/better-auth");
    const lock = await packageLock();
    expect(pkg.version).toBe("1.2.0");
    expect(pkg.engines).toEqual({ node: ">=22.0.0" });
    expect(pkg.exports).toEqual({
      ".": {
        "dev-source": "./src/index.ts",
        default: "./dist/index.mjs",
        types: "./dist/index.d.mts",
      },
      "./client": {
        "dev-source": "./src/client.ts",
        default: "./dist/client.mjs",
        types: "./dist/client.d.mts",
      },
    });
    expect((await packageJson("chargebee")).version).toBe("3.23.1");
    expect((await packageJson("better-auth")).version).toBe("1.7.2");
    const lockedPackage = lock.packages["node_modules/@chargebee/better-auth"];
    expect(lockedPackage.resolved).toBe(
      "https://registry.npmjs.org/@chargebee/better-auth/-/better-auth-1.2.0.tgz",
    );
    expect(lockedPackage.integrity).toBe(
      "sha512-DpAlB3/4Jjelee5iDTY3C6EoNtAIWPrHCPK/lNRpacyXCTjhTy8/HB9NyMfot5B2q8Al7biAmASpnQM0reUoVg==",
    );
    expect({
      sha1: "f5420219dc338919478b5171588402882394a1c5",
      integrity: lockedPackage.integrity,
    }).toEqual({
      sha1: "f5420219dc338919478b5171588402882394a1c5",
      integrity: "sha512-DpAlB3/4Jjelee5iDTY3C6EoNtAIWPrHCPK/lNRpacyXCTjhTy8/HB9NyMfot5B2q8Al7biAmASpnQM0reUoVg==",
    });
    expect(Object.keys(rootExports).sort()).toEqual([
      "CHARGEBEE_ERROR_CODES",
      "chargebee",
      "createChargebeeWebhookProcessor",
    ]);
    expect(Object.keys(clientExports).sort()).toEqual([
      "CHARGEBEE_ERROR_CODES",
      "chargebeeClient",
    ]);
    expect(chargebee).toBeTypeOf("function");
    expect(createChargebeeWebhookProcessor).toBeTypeOf("function");
  });

  test("pins all fourteen public code/message/toString objects at both entry points", () => {
    expect(Object.keys(CHARGEBEE_ERROR_CODES).sort()).toEqual(Object.keys(errors).sort());
    for (const [code, message] of Object.entries(errors)) {
      expect(CHARGEBEE_ERROR_CODES[code]).toMatchObject({ code, message });
      expect(CHARGEBEE_ERROR_CODES[code].toString()).toBe(code);
      expect(clientExports.CHARGEBEE_ERROR_CODES[code]).toBe(CHARGEBEE_ERROR_CODES[code]);
    }
  });

  test("pins declaration-only fields and executable mismatches without inventing behavior", async () => {
    const types = await packageText("@chargebee/better-auth", "dist/src/types.d.ts");
    const runtime = await packageText("@chargebee/better-auth", "dist/index.mjs");
    const webhookSource = await packageText("@chargebee/better-auth", "src/webhook-handler.ts");
    expect(types).toContain('"restore-subscription"');
    expect(types).toContain("billingCycles?: number");
    expect(types).toContain("freeTrial?: {");
    expect(types).not.toContain("trialPeriod");
    expect(types).not.toMatch(/interface ChargebeeOptions[\s\S]*?\n\s*schema\??:/);
    expect(runtime).toContain("SubscriptionScheduledCancellationRemoved");
    expect(webhookSource).toContain("WebhookEventType.SubscriptionScheduledCancellationRemoved");
    expect(webhookSource).not.toContain("SubscriptionCancellationScheduled");
    expect(runtime).not.toContain("organization.update");
    expect(runtime).not.toContain("organization.delete");
  });

  test("retains declared returnUrl while stripping unknown create/update fields", () => {
    const { client } = fakeChargebee();
    const plugin = chargebee({ chargebeeClient: client });
    for (const endpoint of [
      plugin.endpoints.createSubscription,
      plugin.endpoints.updateSubscription,
    ]) {
      expect(endpoint.options.body.parse({
        cancelUrl: "/cancel",
        itemPriceId: "price_pro",
        returnUrl: "/retained-but-unused",
        successUrl: "/success",
        unknown: "stripped",
      })).toEqual({
        cancelUrl: "/cancel",
        itemPriceId: "price_pro",
        returnUrl: "/retained-but-unused",
        successUrl: "/success",
      });
    }
  });
});
