import { commetClient } from "@commet/better-auth/client";
import { afterEach, describe, expect, test, vi } from "vitest";

function clientHarness(handler = async (path) => ({
  data: path === "/commet/portal"
    ? { redirect: true, url: "https://portal.commet.test/session" }
    : { path },
  error: null,
})) {
  const calls = [];
  const $fetch = vi.fn(async (path, options) => {
    calls.push({ options, path });
    return handler(path, options);
  });
  return { actions: commetClient().getActions($fetch), calls, $fetch };
}

function allActionInvocations(actions, fetchOptions = undefined) {
  return [
    () => actions.customer.portal(fetchOptions),
    () => actions.subscription.get(fetchOptions),
    () => actions.subscription.cancel({ immediate: true, reason: "done" }, fetchOptions),
    () => actions.features.list(fetchOptions),
    () => actions.features.get("reports", fetchOptions),
    () => actions.features.check("reports", fetchOptions),
    () => actions.features.canUse("reports", fetchOptions),
    () => actions.usage.track({ feature: "reports", value: 2 }, fetchOptions),
    () => actions.seats.list(fetchOptions),
    () => actions.seats.add({ count: 2, featureCode: "members" }, fetchOptions),
    () => actions.seats.remove({ count: 1, featureCode: "members" }, fetchOptions),
    () => actions.seats.set({ count: 4, featureCode: "members" }, fetchOptions),
    () => actions.seats.setAll({ admins: 1, members: 4 }, fetchOptions),
  ];
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("@commet/better-auth@8.1.0 official client oracle", () => {
  test("pins all 13 action paths, methods, and generated bodies", async () => {
    const { actions, calls } = clientHarness();
    const results = [];
    for (const invoke of allActionInvocations(actions)) results.push(await invoke());

    expect(calls).toEqual([
      { path: "/commet/portal", options: { method: "GET" } },
      { path: "/commet/subscription", options: { method: "GET" } },
      {
        path: "/commet/subscription/cancel",
        options: { body: { immediate: true, reason: "done" }, method: "POST" },
      },
      { path: "/commet/features", options: { method: "GET" } },
      { path: "/commet/features/reports", options: { method: "GET" } },
      { path: "/commet/features/reports/check", options: { method: "GET" } },
      { path: "/commet/features/reports/can-use", options: { method: "GET" } },
      {
        path: "/commet/usage/track",
        options: { body: { feature: "reports", value: 2 }, method: "POST" },
      },
      { path: "/commet/seats", options: { method: "GET" } },
      {
        path: "/commet/seats/add",
        options: { body: { count: 2, featureCode: "members" }, method: "POST" },
      },
      {
        path: "/commet/seats/remove",
        options: { body: { count: 1, featureCode: "members" }, method: "POST" },
      },
      {
        path: "/commet/seats/set",
        options: { body: { count: 4, featureCode: "members" }, method: "POST" },
      },
      {
        path: "/commet/seats/set-all",
        options: { body: { seats: { admins: 1, members: 4 } }, method: "POST" },
      },
    ]);
    expect(results[0]).toEqual({ redirect: true, url: "https://portal.commet.test/session" });
    expect(results.slice(1).every((result) => result.error === null)).toBe(true);
  });

  test("spreads caller fetch options last for every action", async () => {
    const { actions, calls } = clientHarness();
    const override = {
      body: { overridden: true },
      headers: { "x-oracle": "yes" },
      method: "PATCH",
    };
    for (const invoke of allActionInvocations(actions, override)) await invoke();
    expect(calls).toHaveLength(13);
    for (const { options } of calls) expect(options).toEqual(override);
  });

  test("keeps portal's direct return, browser navigation, and throwing error shape", async () => {
    const location = { href: "https://app.example.test/start" };
    vi.stubGlobal("window", { location });
    const successful = clientHarness();
    await expect(successful.actions.customer.portal()).resolves.toEqual({
      redirect: true,
      url: "https://portal.commet.test/session",
    });
    expect(location.href).toBe("https://portal.commet.test/session");

    const failed = clientHarness(async () => ({
      data: null,
      error: { message: "portal unavailable" },
    }));
    await expect(failed.actions.customer.portal()).rejects.toThrow("portal unavailable");
  });

  test("normalizes an omitted cancel body to an empty object", async () => {
    const { actions, calls } = clientHarness();
    await actions.subscription.cancel();
    expect(calls).toEqual([{
      options: { body: {}, method: "POST" },
      path: "/commet/subscription/cancel",
    }]);
  });
});
