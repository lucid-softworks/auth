import { readFile } from "node:fs/promises";
import { afterEach, describe, expect, test, vi } from "vitest";
import { betterAuth } from "better-auth";
import { testUtils } from "better-auth/plugins";
import { createAdapterFactory } from "@better-auth/core/db/adapter";
import { generateId } from "@better-auth/core/utils/id";

const expected = JSON.parse(
  await readFile(new URL("id-strategy-oracle-1.7.1.json", import.meta.url), "utf8"),
);
const betterAuthPackage = JSON.parse(
  await readFile(new URL("node_modules/better-auth/package.json", import.meta.url), "utf8"),
);

const secret = "p9J!e2W@t5Y#u8I$opASdfGHjKLzXcVb";
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

afterEach(() => vi.restoreAllMocks());

function options(generateIdOption, extra = {}) {
  const database = {};
  if (generateIdOption !== "omitted") database.generateId = generateIdOption;
  return {
    secret,
    baseURL: "http://localhost",
    logger: { disabled: true },
    advanced: { database },
    user: { modelName: "people" },
    plugins: [
      {
        id: "id-oracle-plugin",
        schema: {
          widget: {
            modelName: "widget_rows",
            fields: {
              userId: {
                type: "string",
                required: true,
                references: { model: "user", field: "id" },
              },
            },
          },
        },
      },
    ],
    ...extra,
  };
}

function recordingAdapter({
  generateIdOption = "omitted",
  capabilities = {},
  customIdGenerator,
  createResult,
  extraOptions,
} = {}) {
  const calls = [];
  const method = (name, fallback) => async (input) => {
    calls.push({ method: name, input: structuredClone(input) });
    return typeof fallback === "function" ? fallback(input) : fallback;
  };
  const factory = createAdapterFactory({
    config: {
      adapterId: "oracle",
      adapterName: "oracle",
      usePlural: false,
      customIdGenerator,
      ...capabilities,
    },
    adapter: () => ({
      create: method("create", ({ data }) =>
        createResult === undefined ? data : createResult,
      ),
      update: method("update", ({ update }) => ({ id: 7, ...update })),
      updateMany: method("updateMany", 2),
      findOne: method("findOne", { id: 7, userId: 8 }),
      findMany: method("findMany", [{ id: 7, userId: 8 }]),
      delete: method("delete", undefined),
      deleteMany: method("deleteMany", 3),
      count: method("count", 4),
    }),
  });
  return {
    calls,
    adapter: factory(options(generateIdOption, extraOptions)),
  };
}

function shape(value) {
  return {
    type: typeof value,
    length: typeof value === "string" ? value.length : null,
    base62:
      typeof value === "string" && /^[a-zA-Z0-9]+$/.test(value),
    uuid: typeof value === "string" && uuidPattern.test(value),
  };
}

function callbackShape(source, argument) {
  return {
    source,
    keys: Object.keys(argument),
    model: argument.model,
    hasSize: Object.hasOwn(argument, "size"),
    size: argument.size === undefined ? "undefined" : argument.size,
  };
}

describe("Better Auth 1.7.1 database ID oracle", () => {
  test("pins the package, direct generator defaults, errors, and alphabet order", () => {
    expect(betterAuthPackage.version).toBe(expected.betterAuthVersion);
    expect(shape(generateId())).toEqual({
      type: "string",
      length: expected.defaultLength,
      base62: true,
      uuid: false,
    });
    expect(shape(generateId(0))).toEqual({
      type: "string",
      length: expected.defaultLength,
      base62: true,
      uuid: false,
    });
    expect(() => generateId(-1)).toThrow(expected.errors.invalidLength);

    const bytes = [0, 25, 26, 51, 52, 61];
    vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation((buffer) => {
      for (let index = 0; index < buffer.length; index += 1) {
        buffer[index] = bytes[index % bytes.length];
      }
      return buffer;
    });
    expect(generateId(6)).toBe(expected.alphabetProbe);
  });

  test("pins every strategy, adapter capability branch, and public string output", async () => {
    const uuid = vi
      .spyOn(globalThis.crypto, "randomUUID")
      .mockReturnValue(expected.fixedUuid);
    const rows = [];
    const run = async (name, settings = {}) => {
      const fixture = recordingAdapter(settings);
      const result = await fixture.adapter.create({
        model: "user",
        data: { name: name, email: `${name}@example.com`, emailVerified: false },
        select: ["id"],
      });
      const call = fixture.calls[0].input;
      rows.push({
        name,
        adapterHasId: Object.hasOwn(call.data, "id"),
        adapterId: call.data.id ?? null,
        publicHasId: Object.hasOwn(result, "id"),
        publicId: result.id ?? null,
        publicType: typeof result.id,
      });
    };

    await run("default");
    await run("database-string", {
      generateIdOption: false,
      createResult: { id: "database-id" },
    });
    await run("database-number", {
      generateIdOption: false,
      createResult: { id: 9007199254740992 },
    });
    await run("database-missing", { generateIdOption: false, createResult: {} });
    await run("serial", {
      generateIdOption: "serial",
      createResult: { id: 41 },
    });
    await run("uuid-application", { generateIdOption: "uuid" });
    await run("uuid-native", {
      generateIdOption: "uuid",
      capabilities: { supportsUUIDs: true },
      createResult: { id: expected.fixedUuid },
    });
    await run("callback", {
      generateIdOption: ({ model }) => `callback-${model}`,
    });
    await run("callback-false", {
      generateIdOption: () => false,
      createResult: { id: 52 },
    });
    await run("adapter-callback", {
      customIdGenerator: ({ model }) => `adapter-${model}`,
    });
    await run("disabled", {
      capabilities: { disableIdGeneration: true },
      createResult: { id: 63 },
    });

    expect(rows.map((row) => row.name)).toEqual([
      "default",
      "database-string",
      "database-number",
      "database-missing",
      "serial",
      "uuid-application",
      "uuid-native",
      "callback",
      "callback-false",
      "adapter-callback",
      "disabled",
    ]);
    expect(shape(rows[0].adapterId)).toMatchObject({
      length: expected.defaultLength,
      base62: true,
    });
    expect(rows.slice(1)).toEqual([
      { name: "database-string", adapterHasId: false, adapterId: null, publicHasId: true, publicId: "database-id", publicType: "string" },
      { name: "database-number", adapterHasId: false, adapterId: null, publicHasId: true, publicId: "9007199254740992", publicType: "string" },
      { name: "database-missing", adapterHasId: false, adapterId: null, publicHasId: true, publicId: null, publicType: "undefined" },
      { name: "serial", adapterHasId: false, adapterId: null, publicHasId: true, publicId: "41", publicType: "string" },
      { name: "uuid-application", adapterHasId: true, adapterId: expected.fixedUuid, publicHasId: true, publicId: expected.fixedUuid, publicType: "string" },
      { name: "uuid-native", adapterHasId: false, adapterId: null, publicHasId: true, publicId: expected.fixedUuid, publicType: "string" },
      { name: "callback", adapterHasId: true, adapterId: "callback-user", publicHasId: true, publicId: "callback-user", publicType: "string" },
      { name: "callback-false", adapterHasId: false, adapterId: null, publicHasId: true, publicId: "52", publicType: "string" },
      { name: "adapter-callback", adapterHasId: true, adapterId: "adapter-user", publicHasId: true, publicId: "adapter-user", publicType: "string" },
      { name: "disabled", adapterHasId: false, adapterId: null, publicHasId: true, publicId: "63", publicType: "string" },
    ]);
    expect(uuid).toHaveBeenCalledTimes(1);
  });

  test("pins callback property presence, precedence, remapped plugin models, and counts", async () => {
    const adapterArguments = [];
    const fixture = recordingAdapter({
      generateIdOption: (argument) => {
        adapterArguments.push(argument);
        return `fixed-${argument.model}`;
      },
    });
    const created = await fixture.adapter.create({
      model: "widget",
      data: { userId: "owner" },
    });
    expect(created.id).toBe("fixed-widget");
    expect(callbackShape("adapter", adapterArguments[0])).toEqual({
      source: "adapter",
      ...expected.adapterCallback,
      size: "undefined",
    });
    expect(fixture.calls[0].input).toMatchObject({
      model: "widget_rows",
      data: { id: "fixed-widget", userId: "owner" },
    });
    await fixture.adapter.update({ model: "widget", where: [{ field: "id", value: "fixed-widget" }], update: { userId: "owner" } });
    await fixture.adapter.findOne({ model: "widget", where: [{ field: "id", value: "fixed-widget" }] });
    await fixture.adapter.findMany({ model: "widget", where: [{ field: "userId", value: "owner" }] });
    await fixture.adapter.delete({ model: "widget", where: [{ field: "id", value: "fixed-widget" }] });
    await fixture.adapter.deleteMany({ model: "widget", where: [{ field: "userId", value: "owner" }] });
    expect(await fixture.adapter.count({ model: "widget", where: [] })).toBe(4);
    expect(adapterArguments).toHaveLength(1);
    expect(fixture.calls.map((call) => call.method)).toEqual([
      "create", "update", "findOne", "findMany", "delete", "deleteMany", "count",
    ]);

    const contextArguments = [];
    const auth = betterAuth({
      ...options("omitted"),
      advanced: {
        generateId: (argument) => {
          contextArguments.push(callbackShape("legacy", argument));
          return "legacy-id";
        },
        database: {
          generateId: (argument) => {
            contextArguments.push(callbackShape("database", argument));
            return "database-id";
          },
        },
      },
    });
    const context = await auth.$context;
    expect(context.generateId({ model: "user" })).toBe("legacy-id");
    expect(contextArguments).toEqual([expected.contextCallbacks[0]]);

    const databaseAuth = betterAuth({
      ...options("omitted"),
      advanced: {
        database: {
          generateId: (argument) => {
            contextArguments.push(callbackShape("database", argument));
            return "database-id";
          },
        },
      },
    });
    const databaseContext = await databaseAuth.$context;
    expect(databaseContext.generateId({ model: "session", size: 9 })).toBe("database-id");
    expect(contextArguments).toEqual(expected.contextCallbacks);
  });

  test("pins Test Utils and synthetic-signup context fallbacks", async () => {
    const testAuth = betterAuth({
      secret,
      baseURL: "http://localhost",
      logger: { disabled: true },
      advanced: { database: { generateId: false } },
      plugins: [testUtils()],
    });
    const testContext = await testAuth.$context;
    const first = testContext.test.createUser();
    const second = testContext.test.createUser();
    expect(shape(first.id)).toMatchObject({
      length: expected.testUtilsFallbackLength,
      base62: true,
    });
    expect(shape(second.id)).toMatchObject({
      length: expected.testUtilsFallbackLength,
      base62: true,
    });
    expect(first.id).not.toBe(second.id);

    const calls = [];
    const duplicateAuth = betterAuth({
      secret,
      baseURL: "http://localhost",
      logger: { disabled: true },
      emailAndPassword: {
        enabled: true,
        requireEmailVerification: true,
      },
      advanced: {
        database: {
          generateId: (argument) => {
            calls.push(callbackShape("database", argument));
            return Object.hasOwn(argument, "size") ? false : `stored-${argument.model}`;
          },
        },
      },
    });
    const body = {
      email: "duplicate@example.com",
      name: "Duplicate User",
      password: "correct horse battery staple",
    };
    await duplicateAuth.api.signUpEmail({ body });
    const duplicate = await duplicateAuth.api.signUpEmail({ body });
    expect(shape(duplicate.user.id)).toMatchObject({
      length: expected.defaultLength,
      base62: true,
    });
    expect(calls.map(({ model, hasSize, size }) => ({ model, hasSize, size }))).toEqual([
      { model: "user", hasSize: false, size: "undefined" },
      { model: "account", hasSize: false, size: "undefined" },
      { model: "user", hasSize: true, size: "undefined" },
    ]);
  });

  test("pins forceAllowId falsey, serial coercion, UUID validation, and warnings", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const ordinaryLogs = [];
    const ordinary = recordingAdapter({
      generateIdOption: () => "generated-user",
      extraOptions: {
        logger: { log: (level, message) => ordinaryLogs.push({ level, message }) },
      },
    });
    const supplied = await ordinary.adapter.create({
      model: "user",
      data: { id: "caller-id" },
      select: ["id"],
    });
    expect(supplied.id).toBe("generated-user");
    expect(ordinaryLogs).toContainEqual({ level: "warn", message: expected.warnings.suppliedId });

    const serial = recordingAdapter({ generateIdOption: "serial" });
    for (const { value: input, output } of expected.serialCoercion) {
      const result = await serial.adapter.create({
        model: "user",
        data: { id: input },
        forceAllowId: true,
        select: ["id"],
      });
      expect(result.id ?? null).toBe(output === null ? null : String(output));
    }
    const nan = await serial.adapter.create({
      model: "user",
      data: { id: Number.NaN },
      forceAllowId: true,
      select: ["id"],
    });
    expect(nan.id).toBeUndefined();

    vi.spyOn(globalThis.crypto, "randomUUID").mockReturnValue(expected.fixedUuid);
    const uuidWarnings = vi.spyOn(console, "warn").mockImplementation(() => {});
    const nativeUuid = recordingAdapter({
      generateIdOption: "uuid",
      capabilities: { supportsUUIDs: true },
    });
    const applicationUuid = recordingAdapter({ generateIdOption: "uuid" });
    const valid = await nativeUuid.adapter.create({
      model: "user",
      data: { id: expected.fixedUuid },
      forceAllowId: true,
      select: ["id"],
    });
    const invalidString = await applicationUuid.adapter.create({
      model: "user",
      data: { id: "not-a-uuid" },
      forceAllowId: true,
      select: ["id"],
    });
    const invalidNumber = await applicationUuid.adapter.create({
      model: "user",
      data: { id: 7 },
      forceAllowId: true,
      select: ["id"],
    });
    const nativeNumber = await nativeUuid.adapter.create({
      model: "user",
      data: { id: 7 },
      forceAllowId: true,
      select: ["id"],
    });
    expect(valid.id).toBe(expected.fixedUuid);
    expect(invalidString.id).toBeUndefined();
    expect(invalidNumber.id).toBe(expected.fixedUuid);
    expect(nativeNumber.id).toBeUndefined();
    expect(uuidWarnings.mock.calls.some(([message]) =>
      String(message).includes(expected.warnings.invalidUuid),
    )).toBe(true);
  });

  test("pins unsupported capabilities and the official memory false misconfiguration", async () => {
    expect(() =>
      recordingAdapter({
        generateIdOption: "serial",
        capabilities: { supportsNumericIds: false },
      }),
    ).toThrow(expected.errors.unsupportedSerial);

    const logs = [];
    const auth = betterAuth({
      secret,
      baseURL: "http://localhost",
      logger: { log: (level, message) => logs.push({ level, message }) },
      advanced: { database: { generateId: false } },
    });
    await auth.$context;
    expect(logs).toContainEqual({ level: "error", message: expected.warnings.memoryFalse });
  });
});
