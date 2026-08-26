import { DatabaseSync } from "node:sqlite";
import { readFile } from "node:fs/promises";
import { describe, expect, test } from "vitest";
import { getAuthTables } from "@better-auth/core/db";
import {
  createAdapterFactory,
  initGetDefaultFieldName,
  initGetDefaultModelName,
  initGetFieldName,
  initGetModelName,
} from "@better-auth/core/db/adapter";
import { resolveDatabaseSchemaIndexes } from "@better-auth/core/db/internal";
import { getSchema } from "better-auth/db";
import { getMigrations } from "better-auth/db/migration";
import { generateDrizzleSchema } from "./node_modules/@better-auth/drizzle-adapter/dist/generate-drizzle-schema-huQqmolx.mjs";

const expected = JSON.parse(
  await readFile(new URL("schema-oracle-1.7.1.json", import.meta.url), "utf8"),
);
const betterAuthPackage = JSON.parse(
  await readFile(new URL("node_modules/better-auth/package.json", import.meta.url), "utf8"),
);

function options(database) {
  return {
    secret: "schema-oracle-secret-at-least-thirty-two-bytes",
    ...(database ? { database } : {}),
    advanced: { database: { generateId: "uuid" } },
    user: {
      modelName: "people",
      fields: { email: "mail" },
      additionalFields: {
        locale: { type: "string", required: false },
      },
    },
    session: {
      modelName: "login",
      fields: { userId: "owner_id" },
    },
    account: { modelName: "identity" },
    verification: { modelName: "challenge" },
    plugins: [
      {
        id: "schema-oracle-first",
        schema: {
          user: {
            fields: {
              role: { type: "string", required: true, defaultValue: "member" },
            },
          },
          widget: {
            modelName: "widget_record",
            fields: {
              ownerId: {
                type: "string",
                fieldName: "owner_id",
                required: true,
                index: true,
                references: { model: "user", field: "id", onDelete: "cascade" },
              },
              code: {
                type: "string",
                fieldName: "code_value",
                required: true,
              },
            },
            indexes: [{ fields: ["code"], unique: true }],
          },
          archive: {
            modelName: "archive",
            disableMigration: true,
            fields: { value: { type: "string", required: true } },
          },
        },
      },
      {
        id: "schema-oracle-second",
        schema: {
          widget: {
            modelName: "widget_record",
            fields: { note: { type: "string", required: false } },
          },
          tail: {
            fields: { value: { type: "number", required: true } },
          },
        },
      },
    ],
  };
}

function thrownMessage(callback) {
  try {
    callback();
  } catch (error) {
    return error.message;
  }
  throw new Error("expected callback to throw");
}

function recordingAdapter() {
  const calls = [];
  const record = (method, result) => async (input) => {
    calls.push({ method, input });
    return result(input);
  };
  const factory = createAdapterFactory({
    config: {
      adapterId: "schema-oracle-recorder",
      adapterName: "schema-oracle-recorder",
      usePlural: true,
      supportsUUIDs: true,
      supportsBooleans: false,
      supportsDates: false,
      supportsJSON: false,
    },
    adapter: () => ({
      create: record("create", ({ data }) => ({ id: "stored-id", ...data })),
      update: record("update", ({ update }) => ({
        id: "stored-id",
        name: "before",
        mail: "before@example.com",
        emailVerified: 0,
        ...update,
      })),
      updateMany: record("updateMany", () => 2),
      findOne: record("findOne", () => ({
        id: "stored-id",
        name: "Ada",
        mail: "ada@example.com",
        emailVerified: 1,
      })),
      findMany: record("findMany", () => []),
      delete: record("delete", () => undefined),
      deleteMany: record("deleteMany", () => 3),
      count: record("count", () => 4),
      consumeOne: record("consumeOne", () => ({
        id: "stored-id",
        name: "Ada",
        mail: "ada@example.com",
        emailVerified: 1,
      })),
      incrementOne: record("incrementOne", ({ increment }) => ({
        id: "tail-id",
        value: 4 + increment.value,
      })),
    }),
  });
  const authOptions = options();
  return {
    calls,
    adapter: factory({
      ...authOptions,
      advanced: {
        ...authOptions.advanced,
        database: { ...authOptions.advanced.database, joins: true },
      },
    }),
  };
}

describe("Better Auth 1.7.1 database schema oracle", () => {
  test("pins the package and generic getSchema order, fields, references, and indexes", () => {
    expect(betterAuthPackage.version).toBe(expected.betterAuthVersion);
    const schema = getSchema(options());
    expect(Object.keys(schema)).toEqual(expected.tableOrder);
    for (const [table, fields] of Object.entries(expected.fieldKeys)) {
      expect(Object.keys(schema[table].fields)).toEqual(fields);
    }
    expect(schema.login.fields.owner_id.references).toEqual(
      expected.references["login.owner_id"],
    );
    expect(schema.widget_record.fields.owner_id.references).toEqual(
      expected.references["widget_record.owner_id"],
    );
    expect(schema.identity.indexes).toEqual(expected.indexes.identity);
    expect(schema.widget_record.indexes).toEqual(expected.indexes.widget_record);
    expect(schema.archive.disableMigrations).toBe(true);
    expect(schema.archive.indexes).toBeUndefined();
  });

  test("pins singular, reverse, and adapter-owned plural resolver paths and errors", () => {
    const tables = getAuthTables(options());
    const singularModel = initGetModelName({ schema: tables, usePlural: false });
    const pluralModel = initGetModelName({ schema: tables, usePlural: true });
    const singularField = initGetFieldName({ schema: tables, usePlural: false });
    const pluralField = initGetFieldName({ schema: tables, usePlural: true });
    const reverseModel = initGetDefaultModelName({ schema: tables, usePlural: true });
    const reverseField = initGetDefaultFieldName({ schema: tables, usePlural: false });

    expect(singularModel("user")).toBe(expected.resolvers.singularModel);
    expect(pluralModel("user")).toBe(expected.resolvers.pluralModel);
    expect(singularField({ model: "user", field: "email" })).toBe(
      expected.resolvers.singularField,
    );
    expect(pluralField({ model: "users", field: "email" })).toBe(
      expected.resolvers.pluralField,
    );
    expect(reverseModel("peoples")).toBe(expected.resolvers.reverseModel);
    expect(reverseField({ model: "people", field: "mail" })).toBe(
      expected.resolvers.reverseField,
    );
    expect(thrownMessage(() => reverseModel("missing"))).toBe(expected.errors.model);
    expect(
      thrownMessage(() => reverseField({ model: "user", field: "missing" })),
    ).toBe(expected.errors.field);
    expect(
      thrownMessage(() =>
        resolveDatabaseSchemaIndexes([
          {
            tableName: "widget",
            fields: { value: { type: "string", required: true } },
            indexes: [{ fields: ["missing"] }],
          },
        ]),
      ),
    ).toBe(expected.errors.index);
  });

  test("pins generic getMigrations against an empty adapter-owned SQLite database", async () => {
    const database = new DatabaseSync(":memory:");
    try {
      const migration = await getMigrations(options(database), { throwOnUnsafe: false });
      expect(migration.toBeCreated.map(({ table }) => table)).toEqual(
        expected.migration.createdTables,
      );
      expect(migration.toBeAdded.map(({ table }) => table)).toEqual(
        expected.migration.addedTables,
      );
      expect(migration.toBeAddedIndexes.map(({ name }) => name)).toEqual(
        expected.migration.addedIndexNames,
      );
      expect(migration.unsafeChanges).toEqual([]);
      const sql = await migration.compileMigrations();
      for (const table of expected.migration.createdTables) {
        expect(sql).toContain(`create table \"${table}\"`);
      }
    } finally {
      database.close();
    }
  });

  test("pins empty, whitespace, unknown, and naive plural mappings", () => {
    const schema = getAuthTables({
      secret: options().secret,
      user: {
        modelName: "",
        fields: { email: "   ", unknownCoreField: "ignored_column" },
      },
      plugins: [
        {
          id: "mapping-edges",
          schema: {
            status: {
              modelName: "",
              fields: {
                empty: { type: "string", fieldName: "", required: true },
                whitespace: { type: "string", fieldName: "  ", required: true },
              },
            },
            person: {
              modelName: "people",
              fields: { value: { type: "string", required: true } },
            },
          },
        },
      ],
    });
    const pluralModel = initGetModelName({ schema, usePlural: true });
    const pluralField = initGetFieldName({ schema, usePlural: true });

    expect(schema.user.modelName).toBe("user");
    expect(schema.user.fields.email.fieldName).toBe("   ");
    expect(schema.user.fields.unknownCoreField).toBeUndefined();
    expect(schema.status.modelName).toBe("status");
    expect(pluralModel("status")).toBe("statuss");
    expect(pluralModel("person")).toBe("peoples");
    expect(pluralField({ model: "statuss", field: "empty" })).toBe("empty");
    expect(pluralField({ model: "statuss", field: "whitespace" })).toBe("  ");
  });

  test("pins simultaneous core and rate-limit field mappings", () => {
    const schema = getAuthTables({
      secret: options().secret,
      user: {
        modelName: "people",
        fields: {
          name: "display_name",
          email: "mail_address",
          emailVerified: "mail_verified",
          image: "avatar_url",
          createdAt: "user_created_at",
          updatedAt: "user_updated_at",
        },
      },
      session: {
        modelName: "login",
        fields: {
          expiresAt: "expires_at",
          token: "bearer_token",
          createdAt: "session_created_at",
          updatedAt: "session_updated_at",
          ipAddress: "ip_address",
          userAgent: "user_agent",
          userId: "owner_id",
        },
      },
      account: {
        modelName: "identity",
        fields: {
          issuer: "authority",
          accountId: "subject",
          providerId: "provider",
          userId: "account_owner_id",
          accessToken: "access_token_value",
          refreshToken: "refresh_token_value",
          idToken: "identity_token_value",
          accessTokenExpiresAt: "access_token_expires_at",
          refreshTokenExpiresAt: "refresh_token_expires_at",
          scope: "grants",
          password: "password_hash",
          createdAt: "account_created_at",
          updatedAt: "account_updated_at",
        },
      },
      verification: {
        modelName: "challenge",
        fields: {
          identifier: "lookup_key",
          value: "challenge_value",
          expiresAt: "challenge_expires_at",
          createdAt: "challenge_created_at",
          updatedAt: "challenge_updated_at",
        },
      },
      rateLimit: {
        storage: "database",
        modelName: "request_bucket",
        fields: {
          key: "bucket_key",
          count: "hit_count",
          lastRequest: "last_seen_at",
        },
      },
    });
    const fieldNames = (model) =>
      Object.fromEntries(
        Object.entries(schema[model].fields).map(([field, attributes]) => [
          field,
          attributes.fieldName,
        ]),
      );

    expect(fieldNames("user")).toEqual({
      name: "display_name",
      email: "mail_address",
      emailVerified: "mail_verified",
      image: "avatar_url",
      createdAt: "user_created_at",
      updatedAt: "user_updated_at",
    });
    expect(fieldNames("session")).toEqual({
      expiresAt: "expires_at",
      token: "bearer_token",
      createdAt: "session_created_at",
      updatedAt: "session_updated_at",
      ipAddress: "ip_address",
      userAgent: "user_agent",
      userId: "owner_id",
    });
    expect(fieldNames("account")).toEqual({
      issuer: "authority",
      accountId: "subject",
      providerId: "provider",
      userId: "account_owner_id",
      accessToken: "access_token_value",
      refreshToken: "refresh_token_value",
      idToken: "identity_token_value",
      accessTokenExpiresAt: "access_token_expires_at",
      refreshTokenExpiresAt: "refresh_token_expires_at",
      scope: "grants",
      password: "password_hash",
      createdAt: "account_created_at",
      updatedAt: "account_updated_at",
    });
    expect(fieldNames("verification")).toEqual({
      identifier: "lookup_key",
      value: "challenge_value",
      expiresAt: "challenge_expires_at",
      createdAt: "challenge_created_at",
      updatedAt: "challenge_updated_at",
    });
    expect(fieldNames("rateLimit")).toEqual({
      key: "bucket_key",
      count: "hit_count",
      lastRequest: "last_seen_at",
    });
  });

  test("pins host additionalFields overwrite of core and plugin fields", () => {
    const config = {
      secret: options().secret,
      user: {
        additionalFields: {
          email: {
            type: "boolean",
            required: false,
            fieldName: "host_email",
          },
          pluginPreference: {
            type: "number",
            required: true,
            fieldName: "host_preference",
          },
        },
      },
      plugins: [
        {
          id: "host-overwrite",
          schema: {
            user: {
              fields: {
                email: {
                  type: "number",
                  required: true,
                  fieldName: "plugin_email",
                },
                pluginPreference: {
                  type: "string",
                  required: false,
                  fieldName: "plugin_preference",
                },
              },
            },
          },
        },
      ],
    };
    const logical = getAuthTables(config);
    const physical = getSchema(config);

    expect(logical.user.fields.email).toMatchObject({
      type: "boolean",
      required: false,
      fieldName: "host_email",
    });
    expect(logical.user.fields.pluginPreference).toMatchObject({
      type: "number",
      required: true,
      fieldName: "host_preference",
    });
    expect(physical.user.fields.host_email).toBe(logical.user.fields.email);
    expect(physical.user.fields.host_preference).toBe(
      logical.user.fields.pluginPreference,
    );
    expect(physical.user.fields.plugin_email).toBeUndefined();
    expect(physical.user.fields.plugin_preference).toBeUndefined();
  });

  test("pins duplicate model and field first-match and physical overwrite behavior", () => {
    const config = {
      secret: options().secret,
      plugins: [
        {
          id: "duplicates",
          schema: {
            alpha: {
              modelName: "shared",
              fields: {
                first: {
                  type: "string",
                  fieldName: "duplicate",
                  required: true,
                  defaultValue: "first",
                },
                second: {
                  type: "string",
                  fieldName: "duplicate",
                  required: true,
                  defaultValue: "second",
                },
              },
            },
            beta: {
              modelName: "shared",
              fields: { tail: { type: "number", required: true } },
            },
          },
        },
      ],
    };
    const tables = getAuthTables(config);
    const reverseModel = initGetDefaultModelName({ schema: tables, usePlural: false });
    const reverseField = initGetDefaultFieldName({ schema: tables, usePlural: false });
    const physical = getSchema(config);

    expect(reverseModel("shared")).toBe("alpha");
    expect(reverseField({ model: "alpha", field: "duplicate" })).toBe("first");
    expect(physical.shared.fields.duplicate.defaultValue).toBe("second");
    expect(Object.keys(physical.shared.fields)).toEqual(["duplicate", "tail"]);
  });

  test("pins later plugin model reset, disable inheritance, and explicit re-enable", () => {
    const firstTwo = getAuthTables({
      secret: options().secret,
      plugins: [
        {
          id: "initial",
          schema: {
            record: {
              modelName: "renamed_record",
              disableMigration: true,
              fields: { first: { type: "string", required: true } },
            },
          },
        },
        {
          id: "reset-name",
          schema: {
            record: { fields: { second: { type: "string", required: true } } },
          },
        },
      ],
    });
    expect(firstTwo.record.modelName).toBe("record");
    expect(firstTwo.record.disableMigrations).toBe(true);

    const reEnabled = getAuthTables({
      secret: options().secret,
      plugins: [
        ...[
          {
            id: "initial",
            schema: {
              record: {
                modelName: "renamed_record",
                disableMigration: true,
                fields: { first: { type: "string", required: true } },
              },
            },
          },
          {
            id: "reset-name",
            schema: {
              record: {
                fields: { second: { type: "string", required: true } },
              },
            },
          },
        ],
        {
          id: "re-enable",
          schema: {
            record: {
              disableMigration: false,
              fields: { third: { type: "string", required: true } },
            },
          },
        },
      ],
    });
    expect(reEnabled.record.modelName).toBe("record");
    expect(reEnabled.record.disableMigrations).toBe(false);
    expect(Object.keys(reEnabled.record.fields)).toEqual(["first", "second", "third"]);
  });

  test("pins rate-limit last-write collision and table order", () => {
    const schema = getAuthTables({
      secret: options().secret,
      rateLimit: {
        storage: "database",
        modelName: "request_bucket",
        fields: { key: "bucket_key" },
      },
      plugins: [
        {
          id: "colliding-rate-limit",
          schema: {
            before: { fields: { value: { type: "string", required: true } } },
            rateLimit: {
              modelName: "plugin_rate_limit",
              fields: { pluginOnly: { type: "string", required: true } },
            },
          },
        },
      ],
    });
    expect(Object.keys(schema).at(-1)).toBe("rateLimit");
    expect(schema.rateLimit.modelName).toBe("request_bucket");
    expect(schema.rateLimit.fields.pluginOnly).toBeUndefined();
    expect(schema.rateLimit.fields.key.fieldName).toBe("bucket_key");
  });

  test("pins hostile identifiers and stable long generated index hashing", () => {
    const indexes = resolveDatabaseSchemaIndexes([
      {
        tableName: "hostile table",
        fields: {
          value: {
            type: "string",
            fieldName: "hostile-column",
            required: true,
          },
        },
        indexes: [{ fields: ["value"] }],
      },
      {
        tableName:
          "schema_oracle_extremely_long_table_name_that_exceeds_postgres_limit",
        fields: {
          value: {
            type: "string",
            fieldName: "extremely_long_column_name",
            required: true,
          },
        },
        indexes: [{ fields: ["value"] }],
      },
    ]);
    expect(indexes.get("hostile table")[0].name).toBe(
      "hostile table_hostile-column_idx",
    );
    expect(
      indexes.get(
        "schema_oracle_extremely_long_table_name_that_exceeds_postgres_limit",
      )[0].name,
    ).toBe("schema_oracle_extremely_long_table_name_that_excee_a14ee665_idx");
  });

  test("pins reserved, quoted, mixed-case, spaced, and overlong resolver names", () => {
    const logicalModel =
      'select "Logical Model With Spaces And Mixed Case That Is Intentionally Overlong"';
    const physicalModel =
      'Order "Physical Model With Spaces And Mixed Case That Is Intentionally Overlong"';
    const logicalField =
      'from "Logical Field With Spaces And Mixed Case That Is Intentionally Overlong"';
    const physicalField =
      'Group "Physical Field With Spaces And Mixed Case That Is Intentionally Overlong"';
    const schema = getAuthTables({
      secret: options().secret,
      plugins: [
        {
          id: "hostile-resolvers",
          schema: {
            [logicalModel]: {
              modelName: physicalModel,
              fields: {
                [logicalField]: {
                  type: "string",
                  fieldName: physicalField,
                  required: true,
                },
              },
            },
          },
        },
      ],
    });
    const singularModel = initGetModelName({ schema, usePlural: false });
    const pluralModel = initGetModelName({ schema, usePlural: true });
    const singularField = initGetFieldName({ schema, usePlural: false });
    const pluralField = initGetFieldName({ schema, usePlural: true });
    const reversePluralModel = initGetDefaultModelName({
      schema,
      usePlural: true,
    });
    const reversePluralField = initGetDefaultFieldName({
      schema,
      usePlural: true,
    });

    expect(singularModel(logicalModel)).toBe(physicalModel);
    expect(pluralModel(logicalModel)).toBe(`${physicalModel}s`);
    expect(reversePluralModel(`${physicalModel}s`)).toBe(logicalModel);
    expect(singularField({ model: logicalModel, field: logicalField })).toBe(
      physicalField,
    );
    expect(
      pluralField({ model: `${physicalModel}s`, field: logicalField }),
    ).toBe(physicalField);
    expect(
      reversePluralField({
        model: `${physicalModel}s`,
        field: physicalField,
      }),
    ).toBe(logicalField);
  });

  test("pins indexed table and physical-field collision errors", () => {
    expect(
      thrownMessage(() =>
        resolveDatabaseSchemaIndexes([
          {
            tableName: "shared_table",
            fields: { first: { type: "string", required: true } },
            indexes: [{ fields: ["first"] }],
          },
          {
            tableName: "shared_table",
            fields: { second: { type: "string", required: true } },
            indexes: [],
          },
        ]),
      ),
    ).toBe(
      'Database schema resolves more than one indexed logical table to "shared_table". Define table-level indexes through one logical schema key instead of aliasing multiple keys to the same database table.',
    );
    expect(
      thrownMessage(() =>
        resolveDatabaseSchemaIndexes([
          {
            tableName: "collision_table",
            fields: {
              first: {
                type: "string",
                fieldName: "SharedColumn",
                required: true,
              },
              second: {
                type: "string",
                fieldName: "sharedcolumn",
                required: true,
              },
            },
            indexes: [{ fields: ["first", "second"] }],
          },
        ]),
      ),
    ).toBe(
      'Index on table "collision_table" resolves more than one field to the same database column.',
    );
  });

  test("pins the installed Drizzle generator adapter-owned plural schema", async () => {
    const generated = await generateDrizzleSchema({
      options: {
        secret: options().secret,
        advanced: { database: { generateId: "uuid" } },
        user: { modelName: "person" },
        session: { modelName: "login" },
        account: { modelName: "identity" },
        verification: { modelName: "challenge" },
        plugins: [
          {
            id: "drizzle-plural",
            schema: {
              status: {
                fields: { value: { type: "string", required: true } },
              },
            },
          },
        ],
      },
      provider: "pg",
      adapterConfig: { usePlural: true },
      camelCase: true,
      file: "./schema-oracle-never-written.ts",
    });

    expect(generated.overwrite).toBe(false);
    expect(generated.code.match(/export const \w+ = pgTable\("[^"]+"/g)).toEqual([
      'export const persons = pgTable("persons"',
      'export const logins = pgTable("logins"',
      'export const identitys = pgTable("identitys"',
      'export const challenges = pgTable("challenges"',
      'export const statuss = pgTable("statuss"',
    ]);
  });

  test("pins adapter-factory operation, selection, sort, and join transforms", async () => {
    const { adapter, calls } = recordingAdapter();
    const created = await adapter.create({
      model: "user",
      data: {
        name: "Ada",
        email: "ADA@example.com",
        undeclared: "omitted",
      },
    });
    const createCall = calls.at(-1);
    expect(createCall.input.model).toBe("peoples");
    expect(createCall.input.data).toMatchObject({
      name: "Ada",
      mail: "ADA@example.com",
      emailVerified: 0,
      role: "member",
    });
    expect(createCall.input.data.undeclared).toBeUndefined();
    expect(created).toMatchObject({
      id: "stored-id",
      name: "Ada",
      email: "ADA@example.com",
      emailVerified: false,
      role: "member",
    });

    await adapter.update({
      model: "user",
      where: [{ field: "email", value: "ADA@example.com" }],
      update: { name: "Grace", undeclared: "omitted" },
    });
    const updateCall = calls.at(-1);
    expect(updateCall.input.model).toBe("peoples");
    expect(updateCall.input.where).toEqual([
      {
        field: "mail",
        value: "ADA@example.com",
        operator: "eq",
        connector: "AND",
        mode: "sensitive",
      },
    ]);
    expect(updateCall.input.update.name).toBe("Grace");
    expect(updateCall.input.update.undeclared).toBeUndefined();
    expect(updateCall.input.update.updatedAt).toEqual(expect.any(String));

    await adapter.updateMany({
      model: "tail",
      where: [{ field: "value", value: "4" }],
      update: { value: 5, undeclared: true },
    });
    const updateManyCall = calls.at(-1);
    expect(updateManyCall.input).toMatchObject({
      model: "tails",
      where: [{ field: "value", value: 4 }],
      update: { value: 5 },
    });

    const selected = await adapter.findOne({
      model: "user",
      where: [{ field: "email", value: "ada@example.com" }],
      select: ["email"],
    });
    const selectedCall = calls.at(-1);
    expect(selectedCall.input.model).toBe("peoples");
    expect(selectedCall.input.select).toEqual(["email"]);
    expect(selected).toEqual({ email: "ada@example.com" });

    const joinSelect = ["email"];
    await adapter.findOne({
      model: "user",
      where: [{ field: "id", value: "stored-id" }],
      select: joinSelect,
      join: { session: true },
    });
    const joinedCall = calls.filter(
      ({ method, input }) => method === "findOne" && input.join,
    ).at(-1);
    expect(joinedCall.input.select).toEqual(["email", "id"]);
    expect(joinedCall.input.join).toEqual({
      logins: {
        on: { from: "id", to: "owner_id" },
        limit: 100,
        relation: "one-to-many",
      },
    });
    expect(calls.at(-1)).toMatchObject({
      method: "findMany",
      input: {
        model: "logins",
        where: [{ field: "owner_id", value: "stored-id" }],
        limit: 100,
      },
    });

    const sortBy = { field: "email", direction: "asc" };
    await adapter.findMany({
      model: "user",
      where: [{ field: "emailVerified", value: "true" }],
      select: ["email"],
      sortBy,
      offset: 2,
      limit: 3,
    });
    const findManyCall = calls.at(-1);
    expect(findManyCall.input).toMatchObject({
      model: "peoples",
      where: [{ field: "emailVerified", value: 1 }],
      select: ["email"],
      sortBy,
      offset: 2,
      limit: 3,
    });

    await adapter.delete({
      model: "user",
      where: [{ field: "email", value: "ada@example.com" }],
    });
    expect(calls.at(-1).input).toMatchObject({
      model: "peoples",
      where: [{ field: "mail", value: "ada@example.com" }],
    });
    await adapter.deleteMany({
      model: "tail",
      where: [{ field: "value", value: "4" }],
    });
    expect(calls.at(-1).input).toMatchObject({
      model: "tails",
      where: [{ field: "value", value: 4 }],
    });
    await adapter.count({
      model: "user",
      where: [{ field: "email", value: "ada@example.com" }],
    });
    expect(calls.at(-1).input.model).toBe("peoples");

    const consumed = await adapter.consumeOne({
      model: "user",
      where: [{ field: "email", value: "ada@example.com" }],
    });
    expect(calls.at(-1).input.model).toBe("peoples");
    expect(consumed.email).toBe("ada@example.com");

    const incremented = await adapter.incrementOne({
      model: "tail",
      where: [{ field: "value", value: "4" }],
      increment: { value: 2 },
      set: { undeclared: "omitted" },
    });
    expect(calls.at(-1).input).toEqual({
      model: "tails",
      where: [
        {
          field: "value",
          value: 4,
          operator: "eq",
          connector: "AND",
          mode: "sensitive",
        },
      ],
      increment: { value: 2 },
      set: {},
    });
    expect(incremented).toMatchObject({ id: "tail-id", value: 6 });
  });
});
