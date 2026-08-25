import { chargebee } from "@chargebee/better-auth";
import { describe, expect, test, vi } from "vitest";
import {
  callEndpoint,
  endpointContext,
  fakeAdapter,
  fakeChargebee,
  logger,
  plans,
} from "./helpers.mjs";

function lifecycle(options = {}, contextOverrides = {}) {
  const { client } = fakeChargebee(options.clientOverrides);
  const log = logger();
  const internalAdapter = contextOverrides.internalAdapter ?? { updateUser: vi.fn(async () => undefined) };
  const adapter = contextOverrides.adapter ?? fakeAdapter();
  const plugin = chargebee({ chargebeeClient: client, ...options.pluginOptions });
  const hooks = plugin.init({ adapter, internalAdapter, logger: log }).options.databaseHooks.user;
  return { adapter, client, hooks, internalAdapter, log, plugin };
}

const user = {
  email: "user@example.test",
  emailVerified: true,
  id: "user_1",
  name: "User",
};

describe("@chargebee/better-auth@1.2.0 customer lifecycle oracle", () => {
  test("signup reuses the first email match even when its metadata says organization", async () => {
    const onCustomerCreate = vi.fn(async () => undefined);
    const getCustomerCreateParams = vi.fn(async () => ({ first_name: "unused" }));
    const existing = { id: "customer_org_match", meta_data: { customerType: "organization" } };
    const { client, hooks, internalAdapter } = lifecycle({
      clientOverrides: {
        customer: { list: vi.fn(async () => ({ list: [{ customer: existing }] })) },
      },
      pluginOptions: { createCustomerOnSignUp: true, getCustomerCreateParams, onCustomerCreate },
    });
    await hooks.create.after(user);
    expect(client.customer.list).toHaveBeenCalledWith({ email: { is: user.email }, limit: 1 });
    expect(client.customer.create).not.toHaveBeenCalled();
    expect(getCustomerCreateParams).not.toHaveBeenCalled();
    expect(internalAdapter.updateUser).toHaveBeenCalledWith("user_1", {
      chargebeeCustomerId: "customer_org_match",
    });
    expect(onCustomerCreate).toHaveBeenCalledWith({ chargebeeCustomer: existing, user });
  });

  test("signup custom params receive no request context and spread last over built fields", async () => {
    const getCustomerCreateParams = vi.fn(async () => ({
      email: "override@example.test",
      first_name: "Ada",
      meta_data: { callerOwned: "yes" },
    }));
    const onCustomerCreate = vi.fn(async () => { throw new Error("callback failure"); });
    const { client, hooks, internalAdapter, log } = lifecycle({
      pluginOptions: { createCustomerOnSignUp: true, getCustomerCreateParams, onCustomerCreate },
    });
    await expect(hooks.create.after(user)).resolves.toBeUndefined();
    expect(getCustomerCreateParams).toHaveBeenCalledWith(user);
    expect(getCustomerCreateParams.mock.calls[0]).toHaveLength(1);
    expect(client.customer.create).toHaveBeenCalledWith({
      email: "override@example.test",
      first_name: "Ada",
      meta_data: { callerOwned: "yes" },
    });
    expect(internalAdapter.updateUser).toHaveBeenCalledWith("user_1", {
      chargebeeCustomerId: "customer_created",
    });
    expect(log.error).toHaveBeenCalledWith(
      "Error creating Chargebee customer for user user_1:",
      expect.any(Error),
    );
  });

  test("organization mode disables signup/email hooks and contributes no undocumented org hooks", async () => {
    const { client, hooks, plugin } = lifecycle({
      pluginOptions: {
        createCustomerOnSignUp: true,
        organization: { enabled: true },
      },
    });
    await hooks.create.after(user);
    await hooks.update.after({ ...user, chargebeeCustomerId: "customer_1" });
    expect(client.customer.list).not.toHaveBeenCalled();
    expect(client.customer.update).not.toHaveBeenCalled();
    expect(plugin.init({
      adapter: fakeAdapter(),
      internalAdapter: { updateUser: vi.fn() },
      logger: logger(),
    }).options.databaseHooks).toEqual({ user: expect.any(Object) });
  });

  test("email sync requires a linked user customer and swallows provider failures", async () => {
    const update = vi.fn(async () => { throw new Error("provider unavailable"); });
    const { client, hooks } = lifecycle({ clientOverrides: { customer: { update } } });
    await expect(hooks.update.after({ ...user, chargebeeCustomerId: "customer_1" }))
      .resolves.toBeUndefined();
    expect(client.customer.update).toHaveBeenCalledWith("customer_1", { email: user.email });
    await hooks.update.after(user);
    expect(client.customer.update).toHaveBeenCalledTimes(1);
  });

  test("user deletion attempts immediate provider cancellation then always removes items and rows", async () => {
    const subscriptions = [
      { chargebeeSubscriptionId: "provider_1", id: "local_1" },
      { chargebeeSubscriptionId: "provider_2", id: "local_2" },
      { chargebeeSubscriptionId: null, id: "local_3" },
    ];
    const cancel = vi.fn(async id => {
      if (id === "provider_1") throw new Error("already gone");
      return { subscription: { id } };
    });
    const adapter = fakeAdapter({ findMany: vi.fn(async () => subscriptions) });
    const { hooks, log } = lifecycle({ clientOverrides: { subscription: { cancel } } }, { adapter });
    await hooks.delete.before(user);
    expect(cancel.mock.calls).toEqual([
      ["provider_1", { end_of_term: false }],
      ["provider_2", { end_of_term: false }],
    ]);
    expect(adapter.deleteMany.mock.calls).toEqual(subscriptions.flatMap(subscription => [
      [{ model: "subscriptionItem", where: [{ field: "subscriptionId", value: subscription.id }] }],
      [{ model: "subscription", where: [{ field: "id", value: subscription.id }] }],
    ]));
    expect(log.warn).toHaveBeenCalledWith(
      "Failed to cancel subscription in Chargebee: already gone",
    );
  });

  test("on-demand creation filters organization matches, handles races, and skips signup callback", async () => {
    const onCustomerCreate = vi.fn();
    const getCustomerCreateParams = vi.fn(async (_user, ctx) => ({
      first_name: ctx.context.session.user.name,
      meta_data: { customWins: "yes" },
    }));
    const { client } = fakeChargebee({
      customer: {
        list: vi.fn(async () => ({
          list: [{ customer: { id: "org_customer", meta_data: { customerType: "organization" } } }],
        })),
      },
    });
    const adapter = fakeAdapter({
      create: vi.fn(async ({ data }) => ({ id: "local_future", ...data })),
      findMany: vi.fn(async () => []),
      findOne: vi.fn(async ({ model }) => model === "user"
        ? { chargebeeCustomerId: "race_winner", id: "user_1" }
        : null),
    });
    const plugin = chargebee({
      chargebeeClient: client,
      getCustomerCreateParams,
      onCustomerCreate,
      subscription: { enabled: true, plans },
    });
    const context = endpointContext({ adapter });
    const response = await callEndpoint(plugin.endpoints.createSubscription, {
      body: { cancelUrl: "/cancel", itemPriceId: "price_pro", successUrl: "/success" },
      context,
    });
    expect(response.status).toBe(200);
    expect(getCustomerCreateParams).toHaveBeenCalledWith(context.session.user, expect.any(Object));
    expect(client.customer.create).toHaveBeenCalledWith({
      email: "user@example.test",
      first_name: "User",
      meta_data: { customWins: "yes" },
    });
    expect(client.customer.delete).toHaveBeenCalledWith("customer_created");
    expect(adapter.update).not.toHaveBeenCalledWith(expect.objectContaining({ model: "user" }));
    expect(onCustomerCreate).not.toHaveBeenCalled();
    expect(client.hostedPage.checkoutNewForItems).toHaveBeenCalledWith(
      expect.objectContaining({ customer: { id: "race_winner" } }),
    );
  });
});
