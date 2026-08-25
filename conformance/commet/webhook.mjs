import { webhooks } from "@commet/better-auth";
import { describe, expect, test, vi } from "vitest";
import {
  callWebhook,
  install,
  invokePublic,
  responseJson,
  signWebhook,
  webhookPayload,
  webhookSecret,
} from "./helpers.mjs";

const eventHandlers = {
  "invoice.created": "onInvoiceCreated",
  "payment.failed": "onPaymentFailed",
  "payment.received": "onPaymentReceived",
  "subscription.activated": "onSubscriptionActivated",
  "subscription.canceled": "onSubscriptionCanceled",
  "subscription.created": "onSubscriptionCreated",
  "subscription.plan_changed": "onSubscriptionPlanChanged",
  "subscription.updated": "onSubscriptionUpdated",
};

function webhookInstall(config = {}) {
  return install([webhooks({ secret: webhookSecret, ...config })]);
}

async function expectWebhookError(response, status, message) {
  expect(response.status).toBe(status);
  expect(await responseJson(response)).toEqual({ message });
}

describe("@commet/better-auth@8.1.0 webhook oracle", () => {
  test("dispatches all eight events before the catch-all handler", async () => {
    for (const [event, handlerName] of Object.entries(eventHandlers)) {
      const order = [];
      const specific = vi.fn(async (payload) => order.push(["specific", payload]));
      const onPayload = vi.fn(async (payload) => order.push(["payload", payload]));
      const { plugin } = webhookInstall({ [handlerName]: specific, onPayload });
      const payload = webhookPayload(event);
      const rawBody = JSON.stringify(payload);
      const response = await callWebhook(plugin.endpoints.commetWebhooks, rawBody);
      expect(response.status).toBe(200);
      expect(await responseJson(response)).toEqual({ received: true });
      expect(order).toEqual([["specific", payload], ["payload", payload]]);
    }
  });

  test("sends unknown events and truthy non-object JSON only to onPayload", async () => {
    const onPayload = vi.fn();
    const specific = vi.fn();
    const { plugin } = webhookInstall({ onPayload, onSubscriptionCreated: specific });
    for (const payload of [
      webhookPayload("unknown.event"),
      true,
      1,
      "truthy string",
      ["truthy array"],
    ]) {
      const rawBody = JSON.stringify(payload);
      const response = await callWebhook(plugin.endpoints.commetWebhooks, rawBody);
      expect(response.status).toBe(200);
      expect(await responseJson(response)).toEqual({ received: true });
    }
    expect(specific).not.toHaveBeenCalled();
    expect(onPayload.mock.calls.map(([payload]) => payload)).toEqual([
      webhookPayload("unknown.event"),
      true,
      1,
      "truthy string",
      ["truthy array"],
    ]);
  });

  test("rejects every correctly signed JSON-falsy payload", async () => {
    const { plugin } = webhookInstall();
    for (const rawBody of ["null", "false", "0", '""']) {
      await expectWebhookError(
        await callWebhook(plugin.endpoints.commetWebhooks, rawBody),
        401,
        "Invalid webhook signature",
      );
    }
  });

  test("matches Node Buffer hex decoding quirks", async () => {
    const onPayload = vi.fn();
    const { plugin } = webhookInstall({ onPayload });
    const rawBody = JSON.stringify(webhookPayload());
    const exact = signWebhook(rawBody);
    for (const signature of [
      exact.toUpperCase(),
      `${exact}f`,
      `${exact}not-hex-and-ignored`,
    ]) {
      const response = await callWebhook(plugin.endpoints.commetWebhooks, rawBody, signature);
      expect(response.status).toBe(200);
      expect(await responseJson(response)).toEqual({ received: true });
    }
    for (const signature of ["not-hex", exact.slice(0, -2), "00".repeat(32)]) {
      await expectWebhookError(
        await callWebhook(plugin.endpoints.commetWebhooks, rawBody, signature),
        401,
        "Invalid webhook signature",
      );
    }
  });

  test("pins Better Call raw-body preflight behavior", async () => {
    const { plugin } = webhookInstall();
    const omitted = await invokePublic(plugin, "/commet/webhooks");
    await expectWebhookError(omitted, 400, "Request body is required");

    for (const body of ["", "{"]) {
      const malformed = await invokePublic(plugin, "/commet/webhooks", { body });
      expect(malformed.status).toBe(400);
      expect(await responseJson(malformed)).toEqual({
        code: "BAD_REQUEST",
        message: "Invalid JSON in request body",
      });
    }

    const wrongType = await invokePublic(plugin, "/commet/webhooks", {
      body: JSON.stringify(webhookPayload()),
      contentType: "text/plain",
    });
    expect(wrongType.status).toBe(415);

    const missing = await invokePublic(plugin, "/commet/webhooks", {
      body: webhookPayload(),
    });
    await expectWebhookError(missing, 401, "Invalid webhook signature");
  });

  test("stops after handler failure and exposes only the generic error", async () => {
    const specific = vi.fn(async () => { throw new Error("secret handler detail"); });
    const onPayload = vi.fn();
    const { plugin } = webhookInstall({ onPayload, onSubscriptionCreated: specific });
    const rawBody = JSON.stringify(webhookPayload());
    await expectWebhookError(
      await callWebhook(plugin.endpoints.commetWebhooks, rawBody),
      500,
      "Webhook handler error",
    );
    expect(specific).toHaveBeenCalledOnce();
    expect(onPayload).not.toHaveBeenCalled();
  });

  test("repeats deliveries without deduplication", async () => {
    const specific = vi.fn();
    const onPayload = vi.fn();
    const { plugin } = webhookInstall({ onPayload, onSubscriptionCreated: specific });
    const rawBody = JSON.stringify(webhookPayload());
    const signature = signWebhook(rawBody);
    for (let index = 0; index < 2; index++) {
      const response = await callWebhook(plugin.endpoints.commetWebhooks, rawBody, signature);
      expect(response.status).toBe(200);
    }
    expect(specific).toHaveBeenCalledTimes(2);
    expect(onPayload).toHaveBeenCalledTimes(2);
  });

  test("exposes named-handler payload mutation to the catch-all handler", async () => {
    const specific = vi.fn(async (payload) => {
      payload.data.mutatedBy = "specific";
    });
    const onPayload = vi.fn();
    const { plugin } = webhookInstall({ onPayload, onSubscriptionCreated: specific });
    const rawBody = JSON.stringify(webhookPayload());
    const response = await callWebhook(plugin.endpoints.commetWebhooks, rawBody);
    expect(response.status).toBe(200);
    expect(onPayload).toHaveBeenCalledWith({
      ...webhookPayload(),
      data: { id: "sub_1", mutatedBy: "specific" },
    });
  });
});
