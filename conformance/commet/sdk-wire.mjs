import { API_VERSION, Commet, SDK_VERSION } from "@commet/node";
import { afterEach, describe, expect, test, vi } from "vitest";

function jsonResponse(body = { ok: true }, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    headers: { "content-type": "application/json", ...headers },
    status,
  });
}

function captureSdkFetch(handler = async () => jsonResponse()) {
  const calls = [];
  const fetch = vi.fn(async (input, init) => {
    calls.push({
      body: init.body ?? null,
      headers: Object.fromEntries(new Headers(init.headers)),
      method: init.method,
      signal: init.signal,
      url: String(input),
    });
    return handler(input, init, calls.length);
  });
  vi.stubGlobal("fetch", fetch);
  return { calls, fetch };
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("@commet/node@9.1.0 wire oracle", () => {
  test("pins exact constructor API-key validation", () => {
    expect(() => new Commet(undefined)).toThrow(
      "Cannot read properties of undefined (reading 'apiKey')",
    );
    for (const config of [{}, { apiKey: "" }, { apiKey: null }]) {
      expect(() => new Commet(config)).toThrow("Commet SDK: API key is required");
    }
    for (const apiKey of ["CK_uppercase", "sk_wrong", " ck_space"]) {
      expect(() => new Commet({ apiKey })).toThrow(
        "Commet SDK: Invalid API key format. Expected format: ck_xxx...",
      );
    }
    expect(() => new Commet({ apiKey: 7 })).toThrow(
      "config.apiKey.startsWith is not a function",
    );
    expect(() => new Commet({ apiKey: "ck_" })).not.toThrow();
  });

  test("pins the adapter's complete provider path, query, body, and header contract", async () => {
    expect(API_VERSION).toBe("2026-07-31");
    expect(SDK_VERSION).toBe("9.1.0");
    const { calls } = captureSdkFetch();
    const timeoutSignal = new AbortController().signal;
    const timeout = vi.spyOn(AbortSignal, "timeout").mockReturnValue(timeoutSignal);
    const sdk = new Commet({ apiKey: "ck_oracle", retries: 0, telemetry: false });

    await sdk.customers.list({ externalId: "user/one" });
    await sdk.customers.create({ email: "user@example.com", id: "user/one" });
    await sdk.customers.update({ email: "new@example.com", id: "customer/one" });
    await sdk.portal.getUrl({ customerId: "user/one" });
    await sdk.subscriptions.getActive({ customerId: "user/one" });
    await sdk.subscriptions.cancel({ id: "subscription/one", immediate: true, reason: "done" });
    await sdk.featureAccess.list({ customerId: "user/one" });
    await sdk.featureAccess.get({ code: "feature/one", customerId: "user/one" });
    await sdk.usage.check({ customerId: "user/one", featureCode: "feature/one" });
    await sdk.usage.track(
      { customerId: "user/one", featureCode: "feature/one", value: 2 },
      { idempotencyKey: "caller-key" },
    );
    await sdk.seats.getAllBalances({ customerId: "user/one" });
    await sdk.seats.add({ count: 2, customerId: "user/one", featureCode: "seat/one" }, {});
    await sdk.seats.remove({ count: 1, customerId: "user/one", featureCode: "seat/one" }, {});
    await sdk.seats.set({ count: 4, customerId: "user/one", featureCode: "seat/one" }, {});
    await sdk.seats.setAll({ customerId: "user/one", seats: { members: 4 } }, {});

    expect(calls.map(({ body, method, url }) => ({ body, method, url }))).toEqual([
      { body: null, method: "GET", url: "https://commet.co/api/v1/customers?externalId=user%2Fone" },
      { body: '{"email":"user@example.com","id":"user/one"}', method: "POST", url: "https://commet.co/api/v1/customers" },
      { body: '{"email":"new@example.com"}', method: "PATCH", url: "https://commet.co/api/v1/customers/customer/one" },
      { body: '{"customerId":"user/one"}', method: "POST", url: "https://commet.co/api/v1/portal/sessions" },
      { body: null, method: "GET", url: "https://commet.co/api/v1/subscriptions/active?customerId=user%2Fone" },
      { body: '{"immediate":true,"reason":"done"}', method: "POST", url: "https://commet.co/api/v1/subscriptions/subscription/one/cancel" },
      { body: null, method: "GET", url: "https://commet.co/api/v1/feature-access?customerId=user%2Fone" },
      { body: null, method: "GET", url: "https://commet.co/api/v1/feature-access/feature/one?customerId=user%2Fone" },
      { body: '{"customerId":"user/one","featureCode":"feature/one"}', method: "POST", url: "https://commet.co/api/v1/usage/check" },
      { body: '{"customerId":"user/one","featureCode":"feature/one","value":2}', method: "POST", url: "https://commet.co/api/v1/usage/events" },
      { body: null, method: "GET", url: "https://commet.co/api/v1/seats/balances?customerId=user%2Fone" },
      { body: '{"count":2,"customerId":"user/one","featureCode":"seat/one"}', method: "POST", url: "https://commet.co/api/v1/seats" },
      { body: '{"count":1,"customerId":"user/one","featureCode":"seat/one"}', method: "POST", url: "https://commet.co/api/v1/seats/remove" },
      { body: '{"count":4,"customerId":"user/one","featureCode":"seat/one"}', method: "PUT", url: "https://commet.co/api/v1/seats" },
      { body: '{"customerId":"user/one","seats":{"members":4}}', method: "PUT", url: "https://commet.co/api/v1/seats/bulk" },
    ]);
    expect(timeout).toHaveBeenCalledTimes(15);
    expect(timeout.mock.calls.every(([milliseconds]) => milliseconds === 30_000)).toBe(true);
    for (const call of calls) {
      expect(call.signal).toBe(timeoutSignal);
      expect(call.headers["commet-version"]).toBe("2026-07-31");
      expect(call.headers["content-type"]).toBe("application/json");
      expect(call.headers["user-agent"]).toBe(
        `commet-node/9.1.0 node/${process.versions.node} ${process.platform}/${process.arch}`,
      );
      expect(call.headers["x-api-key"]).toBe("ck_oracle");
      expect(call.headers["commet-client-info"]).toBeUndefined();
    }
    expect(calls[9].headers["idempotency-key"]).toBe("caller-key");
    expect(calls[1].headers["idempotency-key"]).toBeUndefined();
  });

  test("adds one stable generated idempotency key across default retries", async () => {
    vi.spyOn(AbortSignal, "timeout").mockReturnValue(new AbortController().signal);
    const delays = [];
    vi.spyOn(globalThis, "setTimeout").mockImplementation((callback, delay) => {
      delays.push(delay);
      callback();
      return 1;
    });
    const { calls } = captureSdkFetch(async (_input, _init, attempt) => (
      attempt < 4
        ? jsonResponse({ error: { message: "retry" } }, 500)
        : jsonResponse({ id: "usage_1" })
    ));
    const sdk = new Commet({ apiKey: "ck_oracle", telemetry: false });
    await expect(sdk.usage.track({ customerId: "user_1", featureCode: "reports" }))
      .resolves.toEqual({ id: "usage_1" });
    expect(calls).toHaveLength(4);
    expect(delays).toEqual([1_000, 2_000, 4_000]);
    const keys = calls.map(call => call.headers["idempotency-key"]);
    expect(new Set(keys).size).toBe(1);
    expect(keys[0]).toMatch(/^commet-node-retry-[0-9a-f-]{36}$/);
  });

  test("retries only the pinned statuses and honors positive capped Retry-After", async () => {
    vi.spyOn(AbortSignal, "timeout").mockReturnValue(new AbortController().signal);
    const delays = [];
    vi.spyOn(globalThis, "setTimeout").mockImplementation((callback, delay) => {
      delays.push(delay);
      callback();
      return 1;
    });
    for (const status of [408, 500, 502, 503, 504]) {
      const fetch = vi.fn()
        .mockResolvedValueOnce(jsonResponse({ error: { message: "retry" } }, status))
        .mockResolvedValueOnce(jsonResponse({ ok: true }));
      vi.stubGlobal("fetch", fetch);
      const sdk = new Commet({ apiKey: "ck_oracle", retries: 1, telemetry: false });
      await sdk.featureAccess.list({ customerId: "user_1" });
      expect(fetch).toHaveBeenCalledTimes(2);
    }

    const rateLimited = vi.fn()
      .mockResolvedValueOnce(jsonResponse(
        { error: { message: "rate limited" } },
        429,
        { "retry-after": "31" },
      ))
      .mockResolvedValueOnce(jsonResponse({ ok: true }));
    vi.stubGlobal("fetch", rateLimited);
    await new Commet({ apiKey: "ck_oracle", retries: 1, telemetry: false })
      .featureAccess.list({ customerId: "user_1" });
    expect(delays.at(-1)).toBe(30_000);

    const noDelay = vi.fn(async () => jsonResponse(
      { error: { message: "rate limited" } },
      429,
    ));
    vi.stubGlobal("fetch", noDelay);
    await expect(new Commet({ apiKey: "ck_oracle", retries: 3, telemetry: false })
      .featureAccess.list({ customerId: "user_1" })).rejects.toThrow("rate limited");
    expect(noDelay).toHaveBeenCalledOnce();
  });

  test("performs three retries after the initial attempt for network errors", async () => {
    vi.spyOn(AbortSignal, "timeout").mockReturnValue(new AbortController().signal);
    vi.spyOn(globalThis, "setTimeout").mockImplementation((callback) => {
      callback();
      return 1;
    });
    const fetch = vi.fn(async () => { throw new TypeError("fetch failed"); });
    vi.stubGlobal("fetch", fetch);
    const sdk = new Commet({ apiKey: "ck_oracle", telemetry: false });
    await expect(sdk.featureAccess.list({ customerId: "user_1" }))
      .rejects.toThrow("fetch failed");
    expect(fetch).toHaveBeenCalledTimes(4);
  });

  test("accepts a JSON response larger than two MiB without truncation", async () => {
    vi.spyOn(AbortSignal, "timeout").mockReturnValue(new AbortController().signal);
    const content = "x".repeat(2 * 1024 * 1024 + 1);
    captureSdkFetch(async () => jsonResponse({ content }));
    const sdk = new Commet({ apiKey: "ck_oracle", retries: 0, telemetry: false });
    await expect(sdk.featureAccess.list({ customerId: "user_1" }))
      .resolves.toEqual({ content });
  });

  test("does not retry a 429 with duplicate Retry-After values", async () => {
    vi.spyOn(AbortSignal, "timeout").mockReturnValue(new AbortController().signal);
    const headers = new Headers();
    headers.append("retry-after", "1");
    headers.append("retry-after", "2");
    const fetch = vi.fn(async () => jsonResponse(
      { error: { message: "duplicate retry delay" } },
      429,
      headers,
    ));
    vi.stubGlobal("fetch", fetch);
    await expect(new Commet({ apiKey: "ck_oracle", retries: 3, telemetry: false })
      .featureAccess.list({ customerId: "user_1" })).rejects.toThrow("duplicate retry delay");
    expect(fetch).toHaveBeenCalledOnce();
  });
});
