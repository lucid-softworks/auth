import {
  commet,
  commetClient,
  features,
  portal,
  seats,
  subscriptions,
  usage,
  webhooks,
} from "@commet/better-auth";
import * as clientExports from "@commet/better-auth/client";
import * as rootExports from "@commet/better-auth";
import { describe, expect, test } from "vitest";
import {
  endpointShape,
  fakeClient,
  install,
  packageVersion,
  webhookSecret,
} from "./helpers.mjs";

const endpointContract = {
  addSeats: ["POST", "/commet/seats/add", 2],
  cancelSubscription: ["POST", "/commet/subscription/cancel", 2],
  canUseFeature: ["GET", "/commet/features/:code/can-use", 2],
  checkFeature: ["GET", "/commet/features/:code/check", 2],
  commetWebhooks: ["POST", "/commet/webhooks", 1],
  getFeature: ["GET", "/commet/features/:code", 2],
  getSubscription: ["GET", "/commet/subscription", 2],
  listFeatures: ["GET", "/commet/features", 2],
  listSeats: ["GET", "/commet/seats", 2],
  portal: ["GET", "/commet/portal", 2],
  removeSeats: ["POST", "/commet/seats/remove", 2],
  setAllSeats: ["POST", "/commet/seats/set-all", 2],
  setSeats: ["POST", "/commet/seats/set", 2],
  trackUsage: ["POST", "/commet/usage/track", 2],
};

describe("@commet/better-auth@8.1.0 composition oracle", () => {
  test("pins package versions, both Better Call resolutions, and exports", async () => {
    expect(await packageVersion("@commet/better-auth")).toBe("8.1.0");
    expect(await packageVersion("@commet/node")).toBe("9.1.0");
    expect(await packageVersion("better-auth")).toBe("1.7.1");
    expect(await packageVersion("better-call-1-3")).toBe("1.3.6");
    expect(await packageVersion("better-call")).toBe("1.4.0");
    expect(await packageVersion("zod")).toBe("4.4.3");
    expect(Object.keys(rootExports).sort()).toEqual([
      "commet",
      "commetClient",
      "features",
      "portal",
      "seats",
      "subscriptions",
      "usage",
      "webhooks",
    ]);
    expect(Object.keys(clientExports)).toEqual(["commetClient"]);
    for (const factory of [clientExports.commetClient, commetClient]) {
      const client = factory();
      expect(client.id).toBe("commet-client");
      expect(client.$InferServerPlugin).toEqual({});
      expect(client.getActions).toBeTypeOf("function");
    }
  });

  test("pins client identity and the six independent sub-plugin groups", () => {
    expect(commetClient()).toMatchObject({ id: "commet-client", $InferServerPlugin: {} });
    const cases = [
      [portal(), ["portal"]],
      [subscriptions(), ["getSubscription", "cancelSubscription"]],
      [features(), ["listFeatures", "getFeature", "checkFeature", "canUseFeature"]],
      [usage(), ["trackUsage"]],
      [seats(), ["listSeats", "addSeats", "removeSeats", "setSeats", "setAllSeats"]],
      [webhooks({ secret: webhookSecret }), ["commetWebhooks"]],
    ];
    for (const [selection, names] of cases) {
      expect(Object.keys(install([selection]).plugin.endpoints)).toEqual(names);
    }
  });

  test("accepts an empty selection, requires use, and composes later values last", () => {
    const empty = install([]).plugin;
    expect(empty).toMatchObject({ id: "commet", endpoints: {} });
    expect(empty.schema).toBeUndefined();
    expect(empty.migrations).toBeUndefined();
    expect(empty.init().options.databaseHooks.user).toHaveProperty("create");
    expect(() => commet({ client: fakeClient() }))
      .toThrow("Cannot read properties of undefined (reading 'map')");

    const first = { marker: "first" };
    const second = { marker: "second" };
    const plugin = commet({
      client: fakeClient(),
      use: [() => ({ duplicate: first }), () => ({ duplicate: second })],
    });
    expect(plugin.endpoints.duplicate).toBe(second);
  });

  test("pins every endpoint descriptor and webhook metadata", () => {
    const plugin = install([
      portal(),
      subscriptions({ plans: { inert: "accepted" } }),
      features(),
      usage(),
      seats(),
      webhooks({ secret: webhookSecret }),
    ]).plugin;
    expect(Object.keys(plugin.endpoints).sort()).toEqual(Object.keys(endpointContract).sort());
    for (const [name, [method, path, middlewareCount]] of Object.entries(endpointContract)) {
      expect(endpointShape(plugin.endpoints[name])).toEqual({
        cloneRequest: name === "commetWebhooks" ? true : undefined,
        isAction: name === "commetWebhooks" ? false : undefined,
        method,
        middlewareCount,
        path,
      });
    }
  });
});
