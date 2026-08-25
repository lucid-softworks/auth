import { commet } from "@commet/better-auth";
import { Webhooks } from "@commet/node";
import { betterAuth } from "better-auth";
import { createHmac } from "node:crypto";
import { readFile } from "node:fs/promises";
import { vi } from "vitest";

export const authSecret = "zS7pFv9Kx3Qm2Wc8Rj6Hd4Nt1Uy5Ba0L";
export const webhookSecret = "commet-oracle-webhook-secret";

export async function packageVersion(path) {
  const packageJson = JSON.parse(await readFile(
    new URL(`../node_modules/${path}/package.json`, import.meta.url),
    "utf8",
  ));
  return packageJson.version;
}

export function fakeClient(overrides = {}) {
  const client = {
    customers: {
      create: vi.fn(async (input) => ({ id: input.id, ...input })),
      list: vi.fn(async () => ({ data: [] })),
      update: vi.fn(async (input) => input),
    },
    featureAccess: {
      get: vi.fn(async (input) => ({ id: "access_1", ...input })),
      list: vi.fn(async () => ({ data: [{ code: "reports" }], next: "ignored" })),
    },
    portal: {
      getUrl: vi.fn(async () => ({ portalUrl: "https://portal.commet.test/session?keep=1" })),
    },
    seats: {
      add: vi.fn(async (input, options) => ({ operation: "add", input, options })),
      getAllBalances: vi.fn(async () => ({ balances: { members: 3 }, ignored: true })),
      remove: vi.fn(async (input, options) => ({ operation: "remove", input, options })),
      set: vi.fn(async (input, options) => ({ operation: "set", input, options })),
      setAll: vi.fn(async (input, options) => ({ data: [{ input, options }], ignored: true })),
    },
    subscriptions: {
      cancel: vi.fn(async (input) => ({ id: input.id, status: "canceled" })),
      getActive: vi.fn(async () => ({ id: "sub_1", status: "active" })),
    },
    usage: {
      check: vi.fn(async (input) => ({ allowed: true, ...input })),
      track: vi.fn(async (input, options) => ({ id: "usage_1", input, options })),
    },
    webhooks: new Webhooks(),
  };

  for (const [resource, methods] of Object.entries(overrides)) {
    client[resource] = typeof methods === "object" && methods !== null
      ? { ...client[resource], ...methods }
      : methods;
  }
  return client;
}

export function install(use, options = {}) {
  const client = options.client ?? fakeClient();
  return {
    client,
    plugin: commet({ client, use, ...options }),
  };
}

export function endpointShape(endpoint) {
  return {
    cloneRequest: endpoint.options.cloneRequest,
    isAction: endpoint.options.metadata?.isAction,
    method: endpoint.options.method,
    middlewareCount: endpoint.options.use?.length ?? 0,
    path: endpoint.path,
  };
}

export async function callAuthenticated(endpoint, input = {}) {
  endpoint.options.use = endpoint.options.use?.slice(1) ?? [];
  return endpoint({
    asResponse: true,
    context: {
      logger: { error: vi.fn(), info: vi.fn(), warn: vi.fn() },
      session: {
        session: { id: "session_1", userId: "user_1" },
        user: {
          email: "user@example.com",
          emailVerified: true,
          id: "user_1",
          name: "User",
        },
      },
    },
    headers: new Headers(),
    ...input,
  });
}

export async function invokePublic(plugin, path, {
  body,
  contentType,
  headers = {},
  method = "POST",
} = {}) {
  const auth = betterAuth({
    baseURL: "https://auth.example.test",
    plugins: [plugin],
    secret: authSecret,
  });
  const requestHeaders = new Headers(headers);
  let requestBody;
  if (body !== undefined) {
    requestBody = typeof body === "string" ? body : JSON.stringify(body);
    requestHeaders.set("content-type", contentType ?? "application/json");
  }
  return auth.handler(new Request(`https://auth.example.test/api/auth${path}`, {
    body: requestBody,
    headers: requestHeaders,
    method,
  }));
}

export async function responseJson(response) {
  return JSON.parse(await response.text());
}

export function signWebhook(rawBody, secret = webhookSecret) {
  return createHmac("sha256", secret).update(rawBody).digest("hex");
}

export async function callWebhook(endpoint, rawBody, signature = signWebhook(rawBody)) {
  return endpoint({
    asResponse: true,
    context: { logger: { error: vi.fn(), info: vi.fn(), warn: vi.fn() } },
    request: new Request("https://auth.example.test/api/auth/commet/webhooks", {
      body: rawBody,
      headers: { "content-type": "application/json", "x-commet-signature": signature },
      method: "POST",
    }),
  });
}

export function webhookPayload(event = "subscription.created", data = { id: "sub_1" }) {
  return { data, event, id: "evt_1" };
}
