import { APIError } from "better-auth/api";
import { describe, expect, test, vi } from "vitest";
import { fakeClient, install } from "./helpers.mjs";

const user = {
  email: "user@example.com",
  emailVerified: false,
  id: "user_1",
  name: "User Name",
};

function lifecycle(options = {}) {
  const installed = install([], options);
  return {
    ...installed,
    hooks: installed.plugin.init().options.databaseHooks.user,
  };
}

function hookContext() {
  return {
    context: { logger: { error: vi.fn(), info: vi.fn(), warn: vi.fn() } },
    request: new Request("https://auth.example.test/api/auth/sign-up/email", {
      body: "{}",
      method: "POST",
    }),
  };
}

async function expectApiError(promise, status, message) {
  try {
    await promise;
    throw new Error("expected APIError");
  } catch (error) {
    expect(error).toBeInstanceOf(APIError);
    expect(error).toMatchObject({ body: { message }, status });
  }
}

describe("@commet/better-auth@8.1.0 customer lifecycle oracle", () => {
  test("installs three hooks but skips them when disabled or context is absent", async () => {
    const disabled = lifecycle({ createCustomerOnSignUp: false });
    expect(Object.keys(disabled.hooks)).toEqual(["create", "update"]);
    expect(disabled.hooks.create).toHaveProperty("before");
    expect(disabled.hooks.create).toHaveProperty("after");
    expect(disabled.hooks.update).toHaveProperty("after");
    expect(disabled.hooks.delete).toBeUndefined();
    await disabled.hooks.create.before(user, hookContext());
    await disabled.hooks.create.after(user, hookContext());
    await disabled.hooks.update.after(user, hookContext());
    expect(disabled.client.customers.list).not.toHaveBeenCalled();
    expect(disabled.client.customers.create).not.toHaveBeenCalled();

    const enabled = lifecycle({ createCustomerOnSignUp: true });
    await enabled.hooks.create.before(user, null);
    await enabled.hooks.create.after(user, null);
    await enabled.hooks.update.after(user, null);
    expect(enabled.client.customers.list).not.toHaveBeenCalled();
    expect(enabled.client.customers.create).not.toHaveBeenCalled();
  });

  test("runs custom params before email validation and preserves that API error", async () => {
    const getCustomerCreateParams = vi.fn(async () => ({ domain: "ignored.test" }));
    const { hooks } = lifecycle({ createCustomerOnSignUp: true, getCustomerCreateParams });
    const context = hookContext();
    await expectApiError(
      hooks.create.before({ ...user, email: "" }, context),
      "BAD_REQUEST",
      "An email is required to create a customer",
    );
    expect(getCustomerCreateParams).toHaveBeenCalledWith(
      { user: { ...user, email: "" } },
      context.request,
    );
  });

  test("matches the exact before-create then unconditional after-create sequence", async () => {
    const getCustomerCreateParams = vi.fn(async () => ({
      domain: "intentionally-not-forwarded.test",
      fullName: "Custom Name",
      metadata: { cohort: "oracle" },
    }));
    const { client, hooks } = lifecycle({
      createCustomerOnSignUp: true,
      getCustomerCreateParams,
    });
    const context = hookContext();
    await hooks.create.before(user, context);
    await hooks.create.after(user, context);

    expect(client.customers.list).toHaveBeenCalledWith({ externalId: "user_1" });
    expect(client.customers.create).toHaveBeenNthCalledWith(1, {
      email: "user@example.com",
      fullName: "Custom Name",
      id: "user_1",
      metadata: { cohort: "oracle" },
    });
    expect(client.customers.create).toHaveBeenNthCalledWith(2, {
      email: "user@example.com",
      id: "user_1",
    });
    expect(JSON.stringify(client.customers.create.mock.calls)).not.toContain("domain");
  });

  test("skips the before create for an existing customer but still performs the after create", async () => {
    const client = fakeClient({
      customers: { list: vi.fn(async () => ({ data: [{ id: "customer_existing" }] })) },
    });
    const { hooks } = lifecycle({ client, createCustomerOnSignUp: true });
    await hooks.create.before(user, hookContext());
    expect(client.customers.create).not.toHaveBeenCalled();
    await hooks.create.after(user, hookContext());
    expect(client.customers.create).toHaveBeenCalledWith({
      email: "user@example.com",
      id: "user_1",
    });
  });

  test("uses the user name fallback and custom full-name precedence", async () => {
    const fallback = lifecycle({
      createCustomerOnSignUp: true,
      getCustomerCreateParams: vi.fn(async () => ({ fullName: null })),
    });
    await fallback.hooks.create.before(user, hookContext());
    expect(fallback.client.customers.create).toHaveBeenCalledWith(expect.objectContaining({
      fullName: "User Name",
    }));

    const custom = lifecycle({
      createCustomerOnSignUp: true,
      getCustomerCreateParams: vi.fn(async () => ({ fullName: "Override" })),
    });
    await custom.hooks.create.before(user, hookContext());
    expect(custom.client.customers.create).toHaveBeenCalledWith(expect.objectContaining({
      fullName: "Override",
    }));
  });

  test("preserves before API errors but wraps ordinary and non-Error failures", async () => {
    const preserved = new APIError("FORBIDDEN", { message: "preserved" });
    const apiClient = fakeClient({
      customers: { list: vi.fn(async () => { throw preserved; }) },
    });
    const api = lifecycle({ client: apiClient, createCustomerOnSignUp: true });
    await expect(api.hooks.create.before(user, hookContext())).rejects.toBe(preserved);

    for (const [failure, message] of [
      [new Error("provider detail"), "Commet customer creation failed: provider detail"],
      [{ secret: true }, "Commet customer creation failed"],
    ]) {
      const client = fakeClient({
        customers: { list: vi.fn(async () => { throw failure; }) },
      });
      const { hooks } = lifecycle({ client, createCustomerOnSignUp: true });
      await expectApiError(hooks.create.before(user, hookContext()), "INTERNAL_SERVER_ERROR", message);
    }
  });

  test("wraps every after-create failure, including an API error", async () => {
    for (const [failure, message] of [
      [new APIError("FORBIDDEN", { message: "inner API error" }), "Commet customer link failed: inner API error"],
      [new Error("provider detail"), "Commet customer link failed: provider detail"],
      [42, "Commet customer link failed"],
    ]) {
      const client = fakeClient({
        customers: { create: vi.fn(async () => { throw failure; }) },
      });
      const { hooks } = lifecycle({ client, createCustomerOnSignUp: true });
      await expectApiError(hooks.create.after(user, hookContext()), "INTERNAL_SERVER_ERROR", message);
    }
  });

  test("updates the first linked customer and suppresses update failures", async () => {
    const client = fakeClient({
      customers: { list: vi.fn(async () => ({ data: [{ id: "customer_1" }, { id: "customer_2" }] })) },
    });
    const { hooks } = lifecycle({ client, createCustomerOnSignUp: true });
    await hooks.update.after({ ...user, email: "new@example.com", name: null }, hookContext());
    expect(client.customers.update).toHaveBeenCalledWith({
      email: "new@example.com",
      fullName: undefined,
      id: "customer_1",
    });

    const failingClient = fakeClient({
      customers: {
        list: vi.fn(async () => ({ data: [{ id: "customer_1" }] })),
        update: vi.fn(async () => { throw new Error("update detail"); }),
      },
    });
    const failing = lifecycle({ client: failingClient, createCustomerOnSignUp: true });
    const context = hookContext();
    await expect(failing.hooks.update.after(user, context)).resolves.toBeUndefined();
    expect(context.context.logger.error).toHaveBeenCalledWith(
      "Commet customer update failed: update detail",
    );
  });

  test("treats a falsy first customer entry as absent", async () => {
    for (const first of [null, false, 0, ""]) {
      const client = fakeClient({
        customers: { list: vi.fn(async () => ({ data: [first, { id: "customer_2" }] })) },
      });
      const { hooks } = lifecycle({ client, createCustomerOnSignUp: true });
      await hooks.create.before(user, hookContext());
      expect(client.customers.create).toHaveBeenCalledWith({
        email: "user@example.com",
        fullName: "User Name",
        id: "user_1",
        metadata: undefined,
      });
    }
  });

  test("maps both null and missing updated names to undefined", async () => {
    for (const updatedUser of [{ ...user, name: null }, { ...user, name: undefined }]) {
      const client = fakeClient({
        customers: { list: vi.fn(async () => ({ data: [{ id: "customer_1" }] })) },
      });
      const { hooks } = lifecycle({ client, createCustomerOnSignUp: true });
      await hooks.update.after(updatedUser, hookContext());
      expect(client.customers.update).toHaveBeenCalledWith({
        email: "user@example.com",
        fullName: undefined,
        id: "customer_1",
      });
    }
  });
});
