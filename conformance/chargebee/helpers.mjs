import { readFile } from "node:fs/promises";
import { vi } from "vitest";

export const authSecret = "zS7pFv9Kx3Qm2Wc8Rj6Hd4Nt1Uy5Ba0L";

export const plans = [{
  billingCycles: 12,
  freeTrial: { days: 7 },
  itemFamilyId: "family_pro",
  itemId: "item_pro",
  itemPriceId: "price_pro",
  limits: { projects: 12 },
  name: "Pro",
  type: "plan",
}];

export async function packageJson(name) {
  return JSON.parse(await readFile(
    new URL(`../node_modules/${name}/package.json`, import.meta.url),
    "utf8",
  ));
}

export async function packageLock() {
  return JSON.parse(await readFile(new URL("../package-lock.json", import.meta.url), "utf8"));
}

export async function packageText(name, path) {
  return readFile(new URL(`../node_modules/${name}/${path}`, import.meta.url), "utf8");
}

export function fakeWebhookHandler() {
  const listeners = new Map();
  const handler = {
    handle: vi.fn(async () => undefined),
    listeners,
    on: vi.fn((event, callback) => {
      listeners.set(event, callback);
      return handler;
    }),
  };
  return handler;
}

export function fakeChargebee(overrides = {}) {
  const handler = overrides.handler ?? fakeWebhookHandler();
  const client = {
    __clientIdentifier: vi.fn(),
    customer: {
      create: vi.fn(async input => ({ customer: { id: "customer_created", ...input } })),
      delete: vi.fn(async id => ({ customer: { id, deleted: true } })),
      list: vi.fn(async () => ({ list: [] })),
      update: vi.fn(async (id, input) => ({ customer: { id, ...input } })),
    },
    hostedPage: {
      checkoutExistingForItems: vi.fn(async () => ({
        hosted_page: { id: "hosted_existing", url: "https://chargebee.test/existing" },
      })),
      checkoutNewForItems: vi.fn(async () => ({
        hosted_page: { id: "hosted_new", url: "https://chargebee.test/new" },
      })),
    },
    portalSession: {
      create: vi.fn(async () => ({
        portal_session: { access_url: "https://chargebee.test/portal" },
      })),
    },
    subscription: {
      cancel: vi.fn(async id => ({ subscription: { id, status: "cancelled" } })),
      list: vi.fn(async () => ({ list: [] })),
      retrieve: vi.fn(async id => ({ subscription: { id, status: "active" } })),
    },
    webhooks: { createHandler: vi.fn(() => handler) },
  };
  for (const [group, value] of Object.entries(overrides)) {
    if (group === "handler") continue;
    client[group] = value && typeof value === "object" && !Array.isArray(value)
      ? { ...client[group], ...value }
      : value;
  }
  return { client, handler };
}

export function fakeAdapter(overrides = {}) {
  return {
    create: vi.fn(async ({ data }) => ({ id: "local_created", ...data })),
    deleteMany: vi.fn(async () => undefined),
    findMany: vi.fn(async () => []),
    findOne: vi.fn(async () => null),
    update: vi.fn(async ({ update }) => ({ id: "local_updated", ...update })),
    ...overrides,
  };
}

export function logger() {
  return { debug: vi.fn(), error: vi.fn(), info: vi.fn(), warn: vi.fn() };
}

export function session(overrides = {}) {
  return {
    session: {
      activeOrganizationId: undefined,
      id: "session_1",
      userId: "user_1",
      ...overrides.session,
    },
    user: {
      chargebeeCustomerId: undefined,
      email: "user@example.test",
      emailVerified: true,
      id: "user_1",
      name: "User",
      ...overrides.user,
    },
  };
}

export function endpointContext(overrides = {}) {
  return {
    adapter: overrides.adapter ?? fakeAdapter(),
    baseURL: "https://auth.example.test/api/auth",
    internalAdapter: overrides.internalAdapter ?? { updateUser: vi.fn(async () => undefined) },
    logger: overrides.logger ?? logger(),
    session: overrides.session ?? session(),
    ...overrides.context,
  };
}

export async function callEndpoint(endpoint, input = {}) {
  endpoint.options.use = [];
  const request = input.request ?? new Request(
    `https://auth.example.test/api/auth${endpoint.path}`,
    { method: endpoint.options.method },
  );
  return endpoint({
    asResponse: true,
    context: input.context ?? endpointContext(),
    headers: input.headers ?? new Headers(),
    request,
    ...input,
  });
}

export async function responseBody(response) {
  const text = await response.text();
  return text ? JSON.parse(text) : null;
}
