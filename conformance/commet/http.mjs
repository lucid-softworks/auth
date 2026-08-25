import { features, portal, seats, subscriptions, usage } from "@commet/better-auth";
import { APIError } from "better-auth/api";
import { describe, expect, test, vi } from "vitest";
import {
  callAuthenticated,
  fakeClient,
  install,
  invokePublic,
  responseJson,
} from "./helpers.mjs";

function allRoutes(client = fakeClient(), portalOptions = {}) {
  return install([
    portal(portalOptions),
    subscriptions(),
    features(),
    usage(),
    seats(),
  ], { client });
}

async function expectBody(response, status, body) {
  expect(response.status).toBe(status);
  expect(await responseJson(response)).toEqual(body);
}

describe("@commet/better-auth@8.1.0 route oracle", () => {
  test("translates all 13 provider calls and projected results", async () => {
    const { client, plugin } = allRoutes();
    const e = plugin.endpoints;
    const responses = await Promise.all([
      callAuthenticated(e.portal),
      callAuthenticated(e.getSubscription),
      callAuthenticated(e.cancelSubscription, { body: { immediate: true, reason: "done" } }),
      callAuthenticated(e.listFeatures),
      callAuthenticated(e.getFeature, { params: { code: "reports" } }),
      callAuthenticated(e.checkFeature, { params: { code: "reports" } }),
      callAuthenticated(e.canUseFeature, { params: { code: "reports" } }),
      callAuthenticated(e.trackUsage, { body: { feature: "reports", value: 2 } }),
      callAuthenticated(e.listSeats),
      callAuthenticated(e.addSeats, { body: { count: 1.5, featureCode: "members" } }),
      callAuthenticated(e.removeSeats, { body: { count: 1, featureCode: "members" } }),
      callAuthenticated(e.setSeats, { body: { count: 4, featureCode: "members" } }),
      callAuthenticated(e.setAllSeats, { body: { seats: { debt: -2, fractional: 1.5 } } }),
    ]);
    const bodies = await Promise.all(responses.map(responseJson));

    expect(bodies[0]).toEqual({
      redirect: true,
      url: "https://portal.commet.test/session?keep=1",
    });
    expect(bodies[1]).toEqual({ id: "sub_1", status: "active" });
    expect(bodies[2]).toEqual({ id: "sub_1", status: "canceled" });
    expect(bodies[3]).toEqual([{ code: "reports" }]);
    expect(bodies[4]).toEqual({ code: "reports", customerId: "user_1", id: "access_1" });
    expect(bodies[5]).toEqual({ allowed: true, customerId: "user_1", featureCode: "reports" });
    expect(bodies[6]).toEqual(bodies[5]);
    expect(bodies[8]).toEqual({ members: 3 });
    expect(bodies[12]).toEqual([{
      input: { customerId: "user_1", seats: { debt: -2, fractional: 1.5 } },
      options: {},
    }]);

    expect(client.portal.getUrl).toHaveBeenCalledWith({ customerId: "user_1" });
    expect(client.subscriptions.getActive).toHaveBeenCalledTimes(2);
    expect(client.subscriptions.cancel).toHaveBeenCalledWith({
      id: "sub_1",
      immediate: true,
      reason: "done",
    });
    expect(client.featureAccess.list).toHaveBeenCalledWith({ customerId: "user_1" });
    expect(client.featureAccess.get).toHaveBeenCalledWith({ code: "reports", customerId: "user_1" });
    expect(client.usage.check).toHaveBeenNthCalledWith(1, {
      customerId: "user_1",
      featureCode: "reports",
    });
    expect(client.usage.check).toHaveBeenNthCalledWith(2, {
      customerId: "user_1",
      featureCode: "reports",
    });
    expect(client.seats.add).toHaveBeenCalledWith({
      count: 1.5,
      customerId: "user_1",
      featureCode: "members",
    }, {});
  });

  test("rewrites only a truthy configured portal return URL", async () => {
    const truthy = allRoutes(fakeClient(), { returnUrl: "https://app.test/settings?tab=billing" });
    const truthyBody = await responseJson(await callAuthenticated(truthy.plugin.endpoints.portal));
    expect(truthyBody.url).toBe(
      "https://portal.commet.test/session?keep=1&return_url=https%3A%2F%2Fapp.test%2Fsettings%3Ftab%3Dbilling",
    );

    const empty = allRoutes(fakeClient(), { returnUrl: "" });
    const emptyBody = await responseJson(await callAuthenticated(empty.plugin.endpoints.portal));
    expect(emptyBody.url).toBe("https://portal.commet.test/session?keep=1");
  });

  test("strips unknown input and preserves JS property order and idempotency quirks", async () => {
    const { client, plugin } = allRoutes();
    const properties = {};
    properties.zeta = "last-string";
    properties["10"] = "ten";
    properties["2"] = "two";
    properties.alpha = "first-string";
    properties["4294967294"] = "max-index";
    properties["4294967295"] = "not-index";

    await callAuthenticated(plugin.endpoints.trackUsage, {
      body: {
        feature: "",
        idempotencyKey: "caller-key",
        properties,
        unknown: "stripped",
        value: 0,
      },
    });
    expect(client.usage.track).toHaveBeenLastCalledWith({
      customerId: "user_1",
      featureCode: "",
      properties: [
        { property: "2", value: "two" },
        { property: "10", value: "ten" },
        { property: "4294967294", value: "max-index" },
        { property: "zeta", value: "last-string" },
        { property: "alpha", value: "first-string" },
        { property: "4294967295", value: "not-index" },
      ],
      value: 0,
    }, { idempotencyKey: "caller-key" });

    await callAuthenticated(plugin.endpoints.trackUsage, {
      body: { feature: "reports", idempotencyKey: "" },
    });
    expect(client.usage.track).toHaveBeenLastCalledWith({
      customerId: "user_1",
      featureCode: "reports",
      properties: undefined,
      value: undefined,
    }, undefined);
  });

  test("validates bodies before session and pins the public session response", async () => {
    const { plugin } = allRoutes();
    await expectBody(
      await invokePublic(plugin, "/commet/usage/track"),
      400,
      { code: "VALIDATION_ERROR", message: "[body] Invalid input: expected object, received undefined" },
    );
    await expectBody(
      await invokePublic(plugin, "/commet/seats/add", { body: { count: 0, featureCode: "members" } }),
      400,
      { code: "VALIDATION_ERROR", message: "[body.count] Too small: expected number to be >=1" },
    );
    await expectBody(
      await invokePublic(plugin, "/commet/subscription/cancel", { body: "null" }),
      400,
      { code: "VALIDATION_ERROR", message: "[body] Invalid input: expected object, received null" },
    );
    await expectBody(
      await invokePublic(plugin, "/commet/features", { method: "GET" }),
      401,
      { code: "UNAUTHORIZED", message: "Unauthorized" },
    );
  });

  test("accepts omitted cancel bodies and rejects cancellation without an active subscription", async () => {
    const client = fakeClient({ subscriptions: { getActive: vi.fn(async () => null) } });
    const { plugin } = allRoutes(client);
    await expectBody(
      await callAuthenticated(plugin.endpoints.cancelSubscription),
      400,
      { message: "No active subscription found" },
    );
    expect(client.subscriptions.getActive).toHaveBeenCalledWith({ customerId: "user_1" });
  });

  test("preserves provider API errors and masks ordinary provider failures", async () => {
    const preservedClient = fakeClient({
      portal: {
        getUrl: vi.fn(async () => {
          throw new APIError("BAD_REQUEST", { message: "provider API error" });
        }),
      },
    });
    const preserved = allRoutes(preservedClient);
    await expectBody(
      await callAuthenticated(preserved.plugin.endpoints.portal),
      400,
      { message: "provider API error" },
    );

    const failingClient = fakeClient({
      featureAccess: { list: vi.fn(async () => { throw new Error("secret provider detail"); }) },
    });
    const failing = allRoutes(failingClient);
    await expectBody(
      await callAuthenticated(failing.plugin.endpoints.listFeatures),
      500,
      { message: "Failed to list features" },
    );
  });
});
