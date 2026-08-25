import {
  chargebee,
  createChargebeeWebhookProcessor,
} from "@chargebee/better-auth";
import Chargebee, { WebhookEventType } from "chargebee";
import { afterEach, describe, expect, test, vi } from "vitest";
import {
  callEndpoint,
  endpointContext,
  fakeAdapter,
  fakeChargebee,
  logger,
  plans,
  responseBody,
} from "./helpers.mjs";

const knownEvents = [
  "subscription_created",
  "subscription_activated",
  "subscription_changed",
  "subscription_renewed",
  "subscription_started",
  "subscription_cancelled",
  "subscription_scheduled_cancellation_removed",
  "customer_deleted",
];

function event(event_type, content = {}) {
  return { content, event_type, id: `event_${event_type}` };
}

function subscription(overrides = {}) {
  return {
    current_term_end: 1_800_000_000,
    current_term_start: 1_700_000_000,
    id: "provider_sub",
    status: "active",
    subscription_items: [{
      amount: 1200,
      item_price_id: "price_pro",
      item_type: "plan",
      quantity: 2,
      unit_price: 600,
    }],
    ...overrides,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("@chargebee/better-auth@1.2.0 webhook oracle", () => {
  test("registers exactly eight mappings, unhandled/error listeners, custom hook, and truthy-pair auth", async () => {
    for (const credentials of [
      {},
      { webhookUsername: "user" },
      { webhookPassword: "pass" },
      { webhookPassword: "pass", webhookUsername: "user" },
    ]) {
      const { client, handler } = fakeChargebee();
      const webhookHandler = vi.fn(instance => {
        expect(instance).toBe(handler);
        instance.on("custom_event", vi.fn());
      });
      const plugin = chargebee({ chargebeeClient: client, webhookHandler, ...credentials });
      const response = await callEndpoint(plugin.endpoints.chargebeeWebhook, {
        body: event("unhandled_oracle"),
      });
      expect(response.status).toBe(200);
      expect(await responseBody(response)).toEqual({ received: true });
      expect([...handler.listeners.keys()]).toEqual([
        ...knownEvents,
        "unhandled_event",
        "error",
        "custom_event",
      ]);
      const createOptions = client.webhooks.createHandler.mock.calls[0][0];
      if (credentials.webhookUsername && credentials.webhookPassword) {
        expect(createOptions.requestValidator).toBeTypeOf("function");
      } else {
        expect(createOptions.requestValidator).toBeUndefined();
      }
      expect(webhookHandler).toHaveBeenCalledBefore(handler.handle);
    }
    expect(WebhookEventType.SubscriptionScheduledCancellationRemoved)
      .toBe("subscription_scheduled_cancellation_removed");
  });

  test("documents the published invalid-auth acknowledgement bug that native code must harden", async () => {
    const client = new Chargebee({ apiKey: "oracle_key", site: "oracle-test" });
    const log = logger();
    const plugin = chargebee({
      chargebeeClient: client,
      webhookPassword: "correct-pass",
      webhookUsername: "correct-user",
    });
    const request = new Request("https://auth.example.test/api/auth/chargebee/webhook", {
      headers: {
        authorization: `Basic ${Buffer.from("wrong:credentials").toString("base64")}`,
      },
      method: "POST",
    });
    const response = await callEndpoint(plugin.endpoints.chargebeeWebhook, {
      body: event("subscription_created"),
      context: endpointContext({ logger: log }),
      request,
    });
    expect(response.status).toBe(200);
    expect(await responseBody(response)).toEqual({ received: true });
    expect(log.warn).toHaveBeenCalledWith(expect.stringContaining("Webhook rejected"));
  });

  test("documents that SDK handle resolves before async queue persistence", async () => {
    const client = new Chargebee({ apiKey: "oracle_key", site: "oracle-test" });
    let release;
    let persisted = false;
    const publish = vi.fn(() => new Promise(resolve => {
      release = () => {
        persisted = true;
        resolve();
      };
    }));
    const plugin = chargebee({
      chargebeeClient: client,
      webhookEventBus: { publish },
      webhookPassword: "pass",
      webhookUsername: "user",
    });
    const request = new Request("https://auth.example.test/api/auth/chargebee/webhook", {
      headers: {
        authorization: `Basic ${Buffer.from("user:pass").toString("base64")}`,
      },
      method: "POST",
    });
    const response = await callEndpoint(plugin.endpoints.chargebeeWebhook, {
      body: event("subscription_created", {
        customer: { id: "customer_1" },
        subscription: subscription(),
      }),
      request,
    });
    expect(publish).toHaveBeenCalledOnce();
    expect(persisted).toBe(false);
    expect(await responseBody(response)).toEqual({ received: true });
    release();
    await new Promise(setImmediate);
    expect(persisted).toBe(true);
  });

  test("created processing persists subscription/items sequentially then calls created and trial", async () => {
    const calls = [];
    const onSubscriptionCreated = vi.fn(async () => calls.push("created"));
    const onTrialStart = vi.fn(async () => calls.push("trial"));
    const adapter = fakeAdapter({
      create: vi.fn(async ({ data, model }) => {
        calls.push(`create:${model}`);
        return { id: model === "subscription" ? "local_created" : "item_created", ...data };
      }),
      findOne: vi.fn(async ({ model }) => model === "user" ? { id: "user_1" } : null),
    });
    const { client } = fakeChargebee();
    const processor = createChargebeeWebhookProcessor({
      chargebeeClient: client,
      subscription: { enabled: true, onSubscriptionCreated, onTrialStart, plans },
    }, { context: { adapter, logger: logger() } });
    await processor.process(event("subscription_created", {
      customer: { id: "customer_1" },
      subscription: subscription({
        meta_data: { subscriptionId: "metadata_pending" },
        trial_end: 1_700_100_000,
        trial_start: 1_700_000_000,
      }),
    }));
    expect(calls).toEqual(["create:subscription", "create:subscriptionItem", "created", "trial"]);
  });

  test("completion lookup updates without replacing items and orders trial before completion", async () => {
    const calls = [];
    const local = { id: "local_pending", referenceId: "user_1", status: "future" };
    const adapter = fakeAdapter({
      create: vi.fn(async () => { calls.push("create"); }),
      deleteMany: vi.fn(async () => { calls.push("delete"); }),
      findOne: vi.fn()
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(local),
      update: vi.fn(async ({ update }) => ({ ...local, ...update })),
    });
    const { client } = fakeChargebee();
    const processor = createChargebeeWebhookProcessor({
      chargebeeClient: client,
      subscription: {
        enabled: true,
        onSubscriptionComplete: vi.fn(async () => calls.push("complete")),
        onTrialStart: vi.fn(async () => calls.push("trial")),
        plans,
      },
    }, { context: { adapter, logger: logger() } });
    await processor.process(event("subscription_activated", {
      customer: { id: "customer_1", meta_data: { pendingSubscriptionId: "local_pending" } },
      subscription: subscription({
        meta_data: { subscriptionId: "metadata_pending" },
        trial_end: 1_700_100_000,
        trial_start: 1_700_000_000,
      }),
    }));
    expect(adapter.findOne.mock.calls.map(([value]) => value.where[0])).toEqual([
      { field: "chargebeeSubscriptionId", value: "provider_sub" },
      { field: "id", value: "metadata_pending" },
      { field: "id", value: "local_pending" },
    ]);
    expect(calls).toEqual(["trial", "complete"]);
    expect(adapter.deleteMany).not.toHaveBeenCalled();
    expect(adapter.create).not.toHaveBeenCalled();
  });

  test("update replaces items then orders newly-cancelled, update, and trial-end callbacks", async () => {
    const calls = [];
    const local = {
      canceledAt: null,
      id: "local_active",
      referenceId: "user_1",
      status: "in_trial",
    };
    const adapter = fakeAdapter({
      create: vi.fn(async ({ model }) => calls.push(`create:${model}`)),
      deleteMany: vi.fn(async () => calls.push("delete-items")),
      findOne: vi.fn(async () => local),
      update: vi.fn(async ({ update }) => ({ ...local, ...update })),
    });
    const { client } = fakeChargebee();
    const processor = createChargebeeWebhookProcessor({
      chargebeeClient: client,
      subscription: {
        enabled: true,
        onSubscriptionCancel: vi.fn(async () => calls.push("cancel")),
        onSubscriptionUpdate: vi.fn(async () => calls.push("update")),
        onTrialEnd: vi.fn(async () => calls.push("trial-end")),
        plans,
      },
    }, { context: { adapter, logger: logger() } });
    await processor.process(event("subscription_scheduled_cancellation_removed", {
      customer: { id: "customer_1" },
      subscription: subscription({ cancelled_at: 1_700_050_000, status: "active" }),
    }));
    expect(calls).toEqual([
      "delete-items",
      "create:subscriptionItem",
      "cancel",
      "update",
      "trial-end",
    ]);
  });

  test("customer deletion removes rows/items and clears metadata plus configured fallback", async () => {
    const adapter = fakeAdapter({
      findMany: vi.fn(async ({ model }) => {
        if (model === "subscription") return [{ id: "local_1" }, { id: "local_2" }];
        if (model === "user") return [{ id: "fallback_user" }];
        return [];
      }),
    });
    const log = logger();
    const { client } = fakeChargebee();
    const processor = createChargebeeWebhookProcessor({ chargebeeClient: client }, {
      auth: { $context: Promise.resolve({ adapter, logger: log }) },
    });
    await processor.process(event("customer_deleted", {
      customer: { id: "customer_1", meta_data: { customerType: "user", userId: "metadata_user" } },
    }));
    expect(adapter.deleteMany).toHaveBeenCalledTimes(4);
    expect(adapter.update.mock.calls).toEqual([
      [{ model: "user", update: { chargebeeCustomerId: null }, where: [{ field: "id", value: "metadata_user" }] }],
      [{ model: "user", update: { chargebeeCustomerId: null }, where: [{ field: "id", value: "fallback_user" }] }],
    ]);
  });
});
