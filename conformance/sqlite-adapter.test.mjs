import { DatabaseSync } from "node:sqlite";
import { readFile } from "node:fs/promises";
import { describe, expect, test } from "vitest";
import {
  createKyselyAdapter,
  getKyselyDatabaseType,
  kyselyAdapter,
} from "@better-auth/kysely-adapter";

const packageMetadata = JSON.parse(
  await readFile(
    new URL("node_modules/@better-auth/kysely-adapter/package.json", import.meta.url),
    "utf8",
  ),
);
const adapterArtifact = await readFile(
  new URL("node_modules/@better-auth/kysely-adapter/dist/index.mjs", import.meta.url),
  "utf8",
);
const nodeDialectArtifact = await readFile(
  new URL(
    "node_modules/@better-auth/kysely-adapter/dist/node-sqlite-dialect.mjs",
    import.meta.url,
  ),
  "utf8",
);
const bunDialectArtifact = await readFile(
  new URL(
    "node_modules/@better-auth/kysely-adapter/dist/bun-sqlite-dialect-C7ftEUSI.mjs",
    import.meta.url,
  ),
  "utf8",
);
const standardIntrospectorArtifact = await readFile(
  new URL(
    "node_modules/kysely/dist/dialect/sqlite/sqlite-introspector.js",
    import.meta.url,
  ),
  "utf8",
);

const secret = "sqlite-adapter-oracle-secret-at-least-32-bytes";

function options(database) {
  return {
    secret,
    database,
    plugins: [
      {
        id: "sqlite-adapter-oracle",
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

function schema(database) {
  database.exec(`
    create table "group" (
      "id" text not null primary key,
      "name" text not null
    );
    create table "probe" (
      "id" text not null primary key,
      "label" text not null,
      "enabled" integer not null,
      "happenedAt" date not null,
      "metadata" text not null,
      "tags" text not null,
      "scores" text not null,
      "counter" integer not null,
      "groupId" text
    );
  `);
}

async function oracle(database) {
  const resolved = await createKyselyAdapter({ database });
  expect(resolved.databaseType).toBe("sqlite");
  expect(resolved.transaction).toBe(true);
  return kyselyAdapter(resolved.kysely, {
    type: "sqlite",
    transaction: resolved.transaction,
  })(options(database));
}

describe("@better-auth/kysely-adapter 1.7.2 local SQLite oracle", () => {
  test("pins recognized local driver families and explicit Kysely transaction policy", async () => {
    expect(packageMetadata.version).toBe("1.7.2");
    expect(getKyselyDatabaseType({ aggregate() {} })).toBe("sqlite");
    expect(getKyselyDatabaseType({ fileControl() {} })).toBe("sqlite");
    expect(
      getKyselyDatabaseType({ open() {}, close() {}, prepare() {} }),
    ).toBe("sqlite");
    expect(getKyselyDatabaseType({ createDriver() {} })).toBeNull();

    const explicit = { marker: "kysely" };
    await expect(
      createKyselyAdapter({
        database: { db: explicit, type: "sqlite", transaction: false },
      }),
    ).resolves.toEqual({
      kysely: explicit,
      databaseType: "sqlite",
      transaction: false,
    });

    expect(adapterArtifact).toContain('if ("aggregate" in db');
    expect(adapterArtifact).toContain('if ("fileControl" in db)');
    expect(adapterArtifact).toContain("db instanceof DatabaseSync");
    expect(adapterArtifact).toContain("transaction = true");
  });

  test("records the standard versus Node and Bun introspection boundary", () => {
    expect(standardIntrospectorArtifact).toContain(
      ".where('type', 'in', ['table', 'view'])",
    );
    expect(nodeDialectArtifact).toContain(
      '.where("type", "=", "table")',
    );
    expect(bunDialectArtifact).toContain(
      '.where("type", "=", "table")',
    );
    expect(nodeDialectArtifact).not.toContain('["table", "view"]');
    expect(bunDialectArtifact).not.toContain('["table", "view"]');
  });

  test("pins Node DatabaseSync CRUD, values, predicates, paging, atomic SQL, and rollback", async () => {
    const database = new DatabaseSync(":memory:");
    schema(database);
    const adapter = await oracle(database);
    const happenedAt = new Date("2024-03-04T05:06:07.089Z");
    try {
      const group = await adapter.create({
        model: "group",
        data: { name: "Example" },
      });
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
        label: "Alpha",
        enabled: true,
        happenedAt,
        metadata: { nested: [1, true] },
        tags: ["one", "two"],
        scores: [2, 3],
        counter: 4,
      });
      expect(
        database
          .prepare('select "enabled", "happenedAt", "metadata", "tags" from "probe" where "id" = ?')
          .get(first.id),
      ).toEqual({
        enabled: 1,
        happenedAt: "2024-03-04T05:06:07.089Z",
        metadata: '{"nested":[1,true]}',
        tags: '["one","two"]',
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
            {
              field: "label",
              value: "ALP",
              operator: "starts_with",
              mode: "insensitive",
            },
            { field: "counter", value: 4, operator: "gte" },
            { field: "counter", value: [10], operator: "not_in" },
          ],
        }),
      ).toBe(2);
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
        probe: [
          expect.objectContaining({ id: first.id, groupId: group.id }),
        ],
      });

      expect(
        await adapter.incrementOne({
          model: "probe",
          where: [{ field: "id", value: first.id }],
          increment: { counter: 3 },
          set: { label: "Updated" },
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
    } finally {
      database.close();
    }
  });
});
