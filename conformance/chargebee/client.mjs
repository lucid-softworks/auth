import { chargebeeClient } from "@chargebee/better-auth/client";
import { createAuthClient } from "better-auth/client";
import { afterEach, describe, expect, test, vi } from "vitest";

const pathMethods = {
  "/subscription/cancel": "POST",
  "/subscription/create": "POST",
  "/subscription/list": "GET",
  "/subscription/portal": "POST",
  "/subscription/update": "POST",
};

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function captureClient(options) {
  const requests = [];
  const customFetchImpl = vi.fn(async (input, init = {}) => {
    const request = input instanceof Request ? input : new Request(input, init);
    requests.push({
      body: request.body ? await request.clone().text() : null,
      method: request.method,
      url: request.url,
    });
    return Response.json({ ok: true });
  });
  return {
    client: createAuthClient({
      baseURL: "https://auth.example.test",
      fetchOptions: { customFetchImpl },
      plugins: [chargebeeClient(options)],
    }),
    requests,
  };
}

describe("@chargebee/better-auth@1.2.0 official client oracle", () => {
  test("pins identity, five explicit methods, and declaration-only subscription option", () => {
    const variants = [chargebeeClient(), chargebeeClient({ subscription: true }), chargebeeClient({ subscription: false })];
    for (const plugin of variants) {
      expect(plugin.id).toBe("chargebee-client");
      expect(plugin.$InferServerPlugin).toEqual({});
      expect(plugin.pathMethods).toEqual(pathMethods);
      expect(Object.keys(plugin)).toEqual([
        "id",
        "$InferServerPlugin",
        "pathMethods",
        "$ERROR_CODES",
      ]);
    }
  });

  test("drives five declared actions plus the inferred GET cancel callback", async () => {
    const { client, requests } = captureClient({ subscription: true });
    expect(client.subscription.cancel).toBeTypeOf("function");
    expect(client.subscription.cancel.callback).toBeTypeOf("function");
    await client.subscription.create({
      cancelUrl: "/cancel",
      itemPriceId: "price_pro",
      successUrl: "/success",
    });
    await client.subscription.update({
      cancelUrl: "/cancel",
      itemPriceId: ["price_pro", "price_addon"],
      successUrl: "/success",
    });
    await client.subscription.list({ query: { customerType: "user", referenceId: "user_1" } });
    await client.subscription.cancel({ returnUrl: "/return" });
    await client.subscription.portal({ returnUrl: "/return" });
    await client.subscription.cancel.callback({
      query: { callbackURL: "/return", subscriptionId: "local_1" },
    });
    expect(requests).toEqual([
      {
        body: '{"cancelUrl":"/cancel","itemPriceId":"price_pro","successUrl":"/success"}',
        method: "POST",
        url: "https://auth.example.test/api/auth/subscription/create",
      },
      {
        body: '{"cancelUrl":"/cancel","itemPriceId":["price_pro","price_addon"],"successUrl":"/success"}',
        method: "POST",
        url: "https://auth.example.test/api/auth/subscription/update",
      },
      {
        body: null,
        method: "GET",
        url: "https://auth.example.test/api/auth/subscription/list?customerType=user&referenceId=user_1",
      },
      {
        body: '{"returnUrl":"/return"}',
        method: "POST",
        url: "https://auth.example.test/api/auth/subscription/cancel",
      },
      {
        body: '{"returnUrl":"/return"}',
        method: "POST",
        url: "https://auth.example.test/api/auth/subscription/portal",
      },
      {
        body: null,
        method: "GET",
        url: "https://auth.example.test/api/auth/subscription/cancel/callback?callbackURL=%2Freturn&subscriptionId=local_1",
      },
    ]);
  });

  test("preserves exact callbackURL casing instead of accepting callbackUrl", async () => {
    const { client, requests } = captureClient({ subscription: false });
    await client.subscription.cancel.callback({
      query: { callbackUrl: "/wrong-case", subscriptionId: "local_1" },
    });
    expect(requests[0].url).toContain("callbackUrl=%2Fwrong-case");
    expect(requests[0].url).not.toContain("callbackURL=");
  });
});
