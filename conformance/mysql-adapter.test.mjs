import { readFile } from "node:fs/promises";
import { describe, expect, test, beforeEach, afterAll } from "vitest";
import { createPool } from "mysql2/promise";
import {
  createKyselyAdapter,
  getKyselyDatabaseType,
  kyselyAdapter,
} from "@better-auth/kysely-adapter";

const databaseUrl = process.env.MYSQL_ORACLE_DATABASE_URL;
const suite = databaseUrl ? describe : describe.skip;
const adapterPackage = JSON.parse(
  await readFile(
    new URL("node_modules/@better-auth/kysely-adapter/package.json", import.meta.url),
    "utf8",
  ),
);
const driverPackage = JSON.parse(
  await readFile(new URL("node_modules/mysql2/package.json", import.meta.url), "utf8"),
);
const artifact = await readFile(
  new URL("node_modules/@better-auth/kysely-adapter/dist/index.mjs", import.meta.url),
  "utf8",
);
const secret = "mysql-adapter-oracle-secret-at-least-32-bytes";
const pool = databaseUrl
  ? createPool({ uri: databaseUrl, timezone: "Z", connectionLimit: 8 })
  : null;

function options(database) {
  return {
    secret,
    database,
    advanced: { database: { joins: true } },
    plugins: [
      {
        id: "mysql-adapter-oracle",
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
          group: {
            fields: { name: { type: "string", required: true } },
          },
        },
      },
    ],
  };
}

async function resetSchema() {
  await pool.query("set foreign_key_checks = 0");
  await pool.query("drop table if exists `probe`");
  await pool.query("drop table if exists `group`");
  await pool.query("set foreign_key_checks = 1");
  await pool.query(`
    create table \`group\` (
      \`id\` varchar(36) not null primary key,
      \`name\` text not null
    )
  `);
  await pool.query(`
    create table \`probe\` (
      \`id\` varchar(36) not null primary key,
      \`label\` text not null,
      \`enabled\` boolean not null,
      \`happenedAt\` timestamp(3) not null,
      \`metadata\` json not null,
      \`tags\` json not null,
      \`scores\` json not null,
      \`counter\` integer not null,
      \`groupId\` varchar(36)
    )
  `);
}

async function oracle() {
  const resolved = await createKyselyAdapter({ database: pool });
  expect(resolved.databaseType).toBe("mysql");
  expect(resolved.transaction).toBe(true);
  return kyselyAdapter(resolved.kysely, {
    type: "mysql",
    transaction: resolved.transaction,
  })(options(pool));
}

suite("@better-auth/kysely-adapter 1.7.1 MySQL oracle", () => {
  beforeEach(resetSchema);
  afterAll(async () => pool?.end());

  test("pins the shipped driver, capabilities, warnings, and lookup order", async () => {
    expect(adapterPackage.version).toBe("1.7.1");
    expect(driverPackage.version).toBe("3.22.5");
    expect(getKyselyDatabaseType(pool)).toBe("mysql");
    expect(artifact).toContain('if (config?.type === "mysql")');
    expect(artifact).toContain("supportsBooleans:");
    expect(artifact).toContain("supportsDates:");
    expect(artifact).toContain("supportsJSON:");
    expect(artifact).toContain("values.id !== void 0 && values.id !== null");
    expect(artifact).toContain("const idEqualityWhere = where.find");
    expect(artifact).toContain("where[0]?.field");
    expect(artifact).toContain("SELECT LAST_INSERT_ID()");
    expect(artifact).toContain("Unable to safely identify the inserted");
    expect(artifact).toContain("Number.MAX_SAFE_INTEGER");

    const explicit = { marker: "kysely" };
    await expect(
      createKyselyAdapter({
        database: { db: explicit, type: "mysql", transaction: false },
      }),
    ).resolves.toEqual({
      kysely: explicit,
      databaseType: "mysql",
      transaction: false,
    });
  });

  test("executes values, predicates, joins, mutation lookup, atomic claims, and rollback", async () => {
    const adapter = await oracle();
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
    const [[raw]] = await pool.query(
      "select `enabled`, cast(`metadata` as char) as `metadata`, cast(`tags` as char) as `tags` from `probe` where `id` = ?",
      [first.id],
    );
    expect(raw).toEqual({
      enabled: 1,
      metadata: '{"nested": [1, true]}',
      tags: '["one", "two"]',
    });

    expect(
      await adapter.findOne({
        model: "probe",
        where: [{ field: "groupId", value: null }],
      }),
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
    ).toMatchObject({
      id: group.id,
      probe: [expect.objectContaining({ id: first.id, groupId: group.id })],
    });

    expect(
      await adapter.update({
        model: "probe",
        where: [{ field: "id", value: first.id }],
        update: { label: "Alpha" },
      }),
    ).toMatchObject({ id: first.id, label: "Alpha" });
    expect(await adapter.update({ model: "probe", where: [], update: { label: "none" } })).toBeNull();
    expect(
      await adapter.incrementOne({
        model: "probe",
        where: [{ field: "id", value: first.id }],
        increment: { counter: 3 },
        set: { counter: 99, label: "Updated" },
      }),
    ).toMatchObject({ counter: 7, label: "Updated" });
    expect(
      await adapter.consumeOne({
        model: "probe",
        where: [{ field: "id", value: first.id }],
      }),
    ).toMatchObject({ id: first.id, counter: 7 });
    expect(
      await adapter.consumeOne({
        model: "probe",
        where: [{ field: "id", value: first.id }],
      }),
    ).toBeNull();

    await expect(
      adapter.transaction(async (transaction) => {
        await transaction.create({ model: "group", data: { name: "rollback" } });
        throw new Error("rollback marker");
      }),
    ).rejects.toThrow("rollback marker");
    expect(
      await adapter.count({
        model: "group",
        where: [{ field: "name", value: "rollback" }],
      }),
    ).toBe(0);
  });
});
