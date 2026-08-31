import { readFile } from "node:fs/promises";
import { afterAll, beforeEach, describe, expect, test } from "vitest";
import {
  createKyselyAdapter,
  getKyselyDatabaseType,
  kyselyAdapter,
} from "@better-auth/kysely-adapter";
import { Kysely, MssqlDialect, sql } from "kysely";
import * as Tarn from "tarn";
import * as Tedious from "tedious";

const databaseUrl = process.env.MSSQL_ORACLE_DATABASE_URL;
const suite = databaseUrl ? describe : describe.skip;
const adapterPackage = JSON.parse(
  await readFile(
    new URL("node_modules/@better-auth/kysely-adapter/package.json", import.meta.url),
    "utf8",
  ),
);
const driverPackage = JSON.parse(
  await readFile(new URL("node_modules/tedious/package.json", import.meta.url), "utf8"),
);
const poolPackage = JSON.parse(
  await readFile(new URL("node_modules/tarn/package.json", import.meta.url), "utf8"),
);
const artifact = await readFile(
  new URL("node_modules/@better-auth/kysely-adapter/dist/index.mjs", import.meta.url),
  "utf8",
);

function parseConnectionString(value) {
  const entries = new Map(
    value
      .split(";")
      .filter(Boolean)
      .map((part) => {
        const separator = part.indexOf("=");
        return [part.slice(0, separator).trim().toLowerCase(), part.slice(separator + 1).trim()];
      }),
  );
  const [server, port = "1433"] = (entries.get("server") ?? "localhost")
    .replace(/^tcp:/, "")
    .split(",");
  return {
    server,
    port: Number(port),
    database: entries.get("database") ?? "master",
    userName: entries.get("user") ?? entries.get("user id") ?? "sa",
    password: entries.get("password") ?? "",
    trustServerCertificate: entries.get("trustservercertificate")?.toLowerCase() !== "false",
  };
}

const connection = databaseUrl ? parseConnectionString(databaseUrl) : null;
const dialect = connection
  ? new MssqlDialect({
      tarn: { ...Tarn, options: { min: 0, max: 8 } },
      tedious: {
        ...Tedious,
        connectionFactory: () =>
          new Tedious.Connection({
            server: connection.server,
            authentication: {
              type: "default",
              options: { userName: connection.userName, password: connection.password },
            },
            options: {
              database: connection.database,
              port: connection.port,
              encrypt: false,
              trustServerCertificate: connection.trustServerCertificate,
              useUTC: true,
            },
          }),
      },
    })
  : null;
const db = dialect ? new Kysely({ dialect }) : null;

function options(database) {
  return {
    secret: "mssql-adapter-oracle-secret-at-least-32-bytes",
    database,
    advanced: { database: { joins: true } },
    plugins: [
      {
        id: "mssql-adapter-oracle",
        schema: {
          probe: {
            fields: {
              label: { type: "string", required: true },
              enabled: { type: "boolean", required: true },
              happenedAt: { type: "date", required: true },
              metadata: { type: "json", required: true },
              tags: { type: "string[]", required: true },
              scores: { type: "number[]", required: true },
              counter: { type: "number", required: true },
              groupId: {
                type: "string",
                required: false,
                references: { model: "group", field: "id" },
              },
            },
          },
          group: { fields: { name: { type: "string", required: true } } },
        },
      },
    ],
  };
}

function oracle(transaction = true) {
  return kyselyAdapter(db, { type: "mssql", transaction })(options(db));
}

async function resetSchema() {
  await sql`drop table if exists [probe]`.execute(db);
  await sql`drop table if exists [group]`.execute(db);
  await sql`
    create table [group] (
      [id] varchar(36) not null primary key,
      [name] varchar(8000) not null
    )
  `.execute(db);
  await sql`
    create table [probe] (
      [id] varchar(36) not null primary key,
      [label] varchar(8000) not null,
      [enabled] smallint not null,
      [happenedAt] datetime2(3) not null,
      [metadata] varchar(8000) not null,
      [tags] varchar(8000) not null,
      [scores] varchar(8000) not null,
      [counter] integer not null,
      [groupId] varchar(36) null
    )
  `.execute(db);
}

suite("@better-auth/kysely-adapter 1.7.1 MSSQL oracle", () => {
  beforeEach(resetSchema);
  afterAll(async () => db?.destroy());

  test("pins the driver, dialect, capabilities, pagination, and OUTPUT paths", async () => {
    expect(adapterPackage.version).toBe("1.7.1");
    expect(driverPackage.version).toBe("19.2.1");
    expect(poolPackage.version).toBe("3.0.2");
    expect(getKyselyDatabaseType(dialect)).toBe("mssql");
    expect(artifact).toContain('if (config?.type === "mssql") return await builder.outputAll("inserted")');
    expect(artifact).toContain('if (config?.type === "mssql") {');
    expect(artifact).toContain("b = b.offset(offset).fetch(limit || 100)");
    expect(artifact).toContain('field: "id"');
    expect(artifact).toContain('outputAll("deleted")');
    expect(artifact).toContain('outputAll("inserted")');
    expect(artifact).toContain('config?.type === "mssql" || config?.type === "mysql"');

    await expect(
      createKyselyAdapter({ database: { db, type: "mssql", transaction: false } }),
    ).resolves.toEqual({ kysely: db, databaseType: "mssql", transaction: false });
  });

  test("executes values, predicates, joins, pagination, mutations, atomic claims, and rollback", async () => {
    const adapter = oracle();
    const happenedAt = new Date("2024-03-04T05:06:07.089Z");
    const group = await adapter.create({ model: "group", data: { name: "Example" } });
    const first = await adapter.create({
      model: "probe",
      data: {
        label: "Alpha",
        enabled: true,
        happenedAt,
        metadata: { nested: [1, true] },
        tags: ["one", "two"],
        scores: [2, 3],
        counter: 4,
        groupId: group.id,
      },
    });
    await adapter.create({
      model: "probe",
      data: {
        label: "alphabet",
        enabled: false,
        happenedAt,
        metadata: { nested: [] },
        tags: [],
        scores: [],
        counter: 8,
        groupId: null,
      },
    });

    expect(first).toMatchObject({
      enabled: true,
      happenedAt,
      metadata: { nested: [1, true] },
      tags: ["one", "two"],
      scores: [2, 3],
    });
    expect(
      await adapter.findOne({ model: "probe", where: [{ field: "groupId", value: null }] }),
    ).toMatchObject({ label: "alphabet" });
    expect(
      await adapter.count({
        model: "probe",
        where: [
          { field: "label", value: "ALP", operator: "starts_with", mode: "insensitive" },
          { field: "counter", value: [4], operator: "in", connector: "OR" },
        ],
      }),
    ).toBe(1);
    expect(
      await adapter.findMany({
        model: "probe",
        where: [{ field: "label", value: "ha", operator: "contains" }],
        sortBy: { field: "counter", direction: "desc" },
        limit: 1,
        offset: 1,
        select: ["label", "counter"],
      }),
    ).toEqual([{ label: "Alpha", counter: 4 }]);
    expect(
      await adapter.findOne({
        model: "group",
        where: [{ field: "id", value: group.id }],
        join: { probe: true },
      }),
    ).toMatchObject({ probe: [expect.objectContaining({ id: first.id })] });

    expect(
      await adapter.update({
        model: "probe",
        where: [{ field: "id", value: first.id }],
        update: { label: "Alpha" },
      }),
    ).toMatchObject({ id: first.id, label: "Alpha" });
    expect(
      await adapter.incrementOne({
        model: "probe",
        where: [{ field: "id", value: first.id }],
        increment: { counter: 3 },
        set: { counter: 99, label: "Updated" },
      }),
    ).toMatchObject({ counter: 7, label: "Updated" });
    expect(
      await adapter.consumeOne({ model: "probe", where: [{ field: "id", value: first.id }] }),
    ).toMatchObject({ id: first.id, counter: 7 });
    expect(
      await adapter.consumeOne({ model: "probe", where: [{ field: "id", value: first.id }] }),
    ).toBeNull();

    await expect(
      adapter.transaction(async (transaction) => {
        await transaction.create({ model: "group", data: { name: "rollback" } });
        throw new Error("rollback marker");
      }),
    ).rejects.toThrow("rollback marker");
    expect(
      await adapter.count({ model: "group", where: [{ field: "name", value: "rollback" }] }),
    ).toBe(0);
  });
});
