import { features, portal, seats, subscriptions, usage } from "@commet/better-auth";
import { describe, expect, test, vi } from "vitest";
import {
  callAuthenticated,
  fakeClient,
  install,
  invokePublic,
  responseJson,
} from "./helpers.mjs";

function routes(client = fakeClient(), portalOptions = {}) {
  return install([
    portal(portalOptions),
    subscriptions(),
    features(),
    usage(),
    seats(),
  ], { client });
}

async function errorBody(response) {
  return { body: await responseJson(response), status: response.status };
}

describe("@commet/better-auth@8.1.0 route edge oracle", () => {
  test("aggregates validation failures in schema order with exact record wording", async () => {
    const { plugin } = routes();
    const seatError = await errorBody(await invokePublic(plugin, "/commet/seats/add", {
      body: { count: 0, featureCode: 7 },
    }));
    const usageError = await errorBody(await invokePublic(plugin, "/commet/usage/track", {
      body: { feature: 7, properties: { region: 9 }, value: "many" },
    }));
    const recordError = await errorBody(await invokePublic(plugin, "/commet/seats/set-all", {
      body: { seats: [1, 2] },
    }));

    expect({ recordError, seatError, usageError }).toMatchInlineSnapshot(`
      {
        "recordError": {
          "body": {
            "code": "VALIDATION_ERROR",
            "message": "[body.seats] Invalid input: expected record, received array",
          },
          "status": 400,
        },
        "seatError": {
          "body": {
            "code": "VALIDATION_ERROR",
            "message": "[body.featureCode] Invalid input: expected string, received number; [body.count] Too small: expected number to be >=1",
          },
          "status": 400,
        },
        "usageError": {
          "body": {
            "code": "VALIDATION_ERROR",
            "message": "[body.feature] Invalid input: expected string, received number; [body.value] Invalid input: expected number, received string; [body.properties.region] Invalid input: expected string, received number",
          },
          "status": 400,
        },
      }
    `);
  });

  test("pins the exact ordinary-route unsupported-media-type response", async () => {
    const { plugin } = routes();
    const response = await invokePublic(plugin, "/commet/usage/track", {
      body: JSON.stringify({ feature: "reports" }),
      contentType: "text/plain",
    });
    expect(await errorBody(response)).toMatchInlineSnapshot(`
      {
        "body": {
          "code": "UNSUPPORTED_MEDIA_TYPE",
          "message": "Content-Type "text/plain" is not allowed. Allowed types: application/json",
        },
        "status": 415,
      }
    `);
  });

  test("rounds integers beyond JS safe precision and rejects parsed non-finite numbers", async () => {
    const { client, plugin } = routes();
    const rounded = await callAuthenticated(plugin.endpoints.trackUsage, {
      body: JSON.parse('{"feature":"reports","value":9007199254740993}'),
    });
    expect(rounded.status).toBe(200);
    expect(client.usage.track).toHaveBeenCalledWith({
      customerId: "user_1",
      featureCode: "reports",
      properties: undefined,
      value: 9_007_199_254_740_992,
    }, undefined);

    const nonFinite = await invokePublic(plugin, "/commet/usage/track", {
      body: '{"feature":"reports","value":1e400}',
    });
    expect(await errorBody(nonFinite)).toMatchInlineSnapshot(`
      {
        "body": {
          "code": "VALIDATION_ERROR",
          "message": "[body.value] Invalid input: expected number, received number",
        },
        "status": 400,
      }
    `);
  });

  test("projects absent portal, feature, and seat fields into exact empty responses", async () => {
    const client = fakeClient({
      featureAccess: { list: vi.fn(async () => ({})) },
      portal: { getUrl: vi.fn(async () => ({})) },
      seats: {
        getAllBalances: vi.fn(async () => ({})),
        setAll: vi.fn(async () => ({})),
      },
    });
    const { plugin } = routes(client);
    const portalResponse = await callAuthenticated(plugin.endpoints.portal);
    expect(await responseJson(portalResponse)).toEqual({ redirect: true });

    for (const response of [
      await callAuthenticated(plugin.endpoints.listFeatures),
      await callAuthenticated(plugin.endpoints.listSeats),
      await callAuthenticated(plugin.endpoints.setAllSeats, { body: { seats: {} } }),
    ]) {
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe("application/json");
      expect(await response.text()).toBe("");
    }
  });

  test("distinguishes an omitted cancel body from an empty JSON request body", async () => {
    const { plugin } = routes();
    const response = await invokePublic(plugin, "/commet/subscription/cancel", { body: "" });
    expect(await errorBody(response)).toMatchInlineSnapshot(`
      {
        "body": {
          "code": "BAD_REQUEST",
          "message": "Invalid JSON in request body",
        },
        "status": 400,
      }
    `);
  });

  test("uses active-subscription truthiness and forwards an undefined ID", async () => {
    for (const inactive of [null, false, 0, ""]) {
      const client = fakeClient({ subscriptions: { getActive: vi.fn(async () => inactive) } });
      const { plugin } = routes(client);
      const response = await callAuthenticated(plugin.endpoints.cancelSubscription);
      expect(await errorBody(response)).toEqual({
        body: { message: "No active subscription found" },
        status: 400,
      });
      expect(client.subscriptions.cancel).not.toHaveBeenCalled();
    }

    const client = fakeClient({ subscriptions: { getActive: vi.fn(async () => true) } });
    const { plugin } = routes(client);
    const response = await callAuthenticated(plugin.endpoints.cancelSubscription);
    expect(response.status).toBe(200);
    expect(client.subscriptions.cancel).toHaveBeenCalledWith({
      id: undefined,
      immediate: undefined,
      reason: undefined,
    });
  });
});
