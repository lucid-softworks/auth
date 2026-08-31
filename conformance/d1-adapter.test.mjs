import { DatabaseSync } from "node:sqlite";
import { readFile } from "node:fs/promises";
import { describe, expect, test } from "vitest";
import { createKyselyAdapter, kyselyAdapter } from "@better-auth/kysely-adapter";
import { getMigrations } from "better-auth/db/migration";

const packageMetadata = JSON.parse(await readFile(
  new URL("node_modules/@better-auth/kysely-adapter/package.json", import.meta.url), "utf8",
));
const dialectArtifact = await readFile(new URL(
  "node_modules/@better-auth/kysely-adapter/dist/d1-sqlite-dialect-D4qp4-wW.mjs", import.meta.url,
), "utf8");

class LocalD1 {
  constructor() {
    this.sqlite = new DatabaseSync(":memory:");
    this.prepared = [];
    this.batches = [];
  }
  prepare(sql) {
    this.prepared.push(sql);
    return new LocalD1Statement(this, sql, []);
  }
  async batch(statements) {
    this.batches.push(statements.map((statement) => statement.sql));
    return Promise.all(statements.map((statement) => statement.all()));
  }
  exec(sql) { this.sqlite.exec(sql); }
  close() { this.sqlite.close(); }
}

class LocalD1Statement {
  constructor(database, sql, parameters) {
    this.database = database;
    this.sql = sql;
    this.parameters = parameters;
  }
  bind(...parameters) { return new LocalD1Statement(this.database, this.sql, parameters); }
  async all() {
    const results = this.database.sqlite.prepare(this.sql).all(...this.parameters);
    const meta = this.database.sqlite.prepare(
      "select changes() as changes, last_insert_rowid() as last_row_id",
    ).get();
    return { results, meta };
  }
}

const secret = "d1-adapter-oracle-secret-at-least-32-bytes";
function options(database) {
  return {
    secret,
    database,
    plugins: [{
      id: "d1-adapter-oracle",
      schema: {
        probe: { fields: {
          label: { type: "string", required: true },
          enabled: { type: "boolean", required: true },
          happenedAt: { type: "date", required: true },
          metadata: { type: "json", required: true },
          payload: { type: "string", required: false },
          counter: { type: "number", required: true },
        } },
      },
    }],
  };
}

describe("@better-auth/kysely-adapter 1.7.2 Cloudflare D1 oracle", () => {
  test("pins prepared all(), metadata, capability failures, and introspection", async () => {
    expect(packageMetadata.version).toBe("1.7.2");
    expect(dialectArtifact).toContain("prepare(compiledQuery.sql).bind(...compiledQuery.parameters).all()");
    expect(dialectArtifact).toContain("results.meta.changes");
    expect(dialectArtifact).toContain("results.meta.last_row_id");
    expect(dialectArtifact).toContain("D1 does not support interactive transactions.");
    expect(dialectArtifact).toContain("D1 does not support streaming queries.");
    expect(dialectArtifact).toContain('where("name", "not like", "_cf_%")');
    expect(dialectArtifact).toContain('prepare("SELECT * FROM pragma_table_info(?)")');

    const database = new LocalD1();
    try {
      database.exec('create table "serial_probe" ("id" INTEGER primary key, "name" text)');
      database.exec('create table "_cf_internal" ("id" integer)');
      database.exec('create view "probe_view" as select * from "serial_probe"');
      const resolved = await createKyselyAdapter({ database });
      expect(resolved.databaseType).toBe("sqlite");
      expect(resolved.transaction).toBe(false);
      const tables = await resolved.kysely.introspection.getTables();
      expect(tables.map((table) => table.name).sort()).toEqual(["probe_view", "serial_probe"]);
      expect(tables.find((table) => table.name === "serial_probe").columns[0].isAutoIncrementing).toBe(true);
      expect(database.batches.at(-1)).toEqual([
        "SELECT * FROM pragma_table_info(?)", "SELECT * FROM pragma_table_info(?)",
      ]);
      await expect(resolved.kysely.transaction().execute(() => undefined)).rejects.toThrow(
        "D1 does not support interactive transactions.",
      );
    } finally { database.close(); }
  });

  test("runs CRUD and security-sensitive operations as bound atomic statements", async () => {
    const database = new LocalD1();
    database.exec(`create table "probe" (
      "id" text not null primary key, "label" text not null, "enabled" integer not null,
      "happenedAt" date not null, "metadata" text not null, "payload" text, "counter" integer not null
    )`);
    try {
      const resolved = await createKyselyAdapter({ database });
      const adapter = kyselyAdapter(resolved.kysely, { type: "sqlite", transaction: resolved.transaction })(options(database));
      const happenedAt = new Date("2024-03-04T05:06:07.089Z");
      const first = await adapter.create({ model: "probe", data: {
        label: "' hostile ? --", enabled: true, happenedAt, metadata: { nested: [1, true] },
        payload: null, counter: 4,
      } });
      expect(first).toMatchObject({ label: "' hostile ? --", enabled: true, happenedAt, counter: 4 });
      expect(await adapter.incrementOne({
        model: "probe", where: [{ field: "id", value: first.id }],
        increment: { counter: 3 }, set: { label: "Updated" },
      })).toMatchObject({ id: first.id, label: "Updated", counter: 7 });
      expect(await adapter.consumeOne({ model: "probe", where: [{ field: "id", value: first.id }] }))
        .toMatchObject({ id: first.id, counter: 7 });
      expect(await adapter.consumeOne({ model: "probe", where: [{ field: "id", value: first.id }] }))
        .toBeNull();
      expect(database.prepared.some((sql) => sql.includes("delete from") && sql.includes("returning"))).toBe(true);
      expect(database.prepared.some((sql) => sql.includes('"counter" = "counter" +'))).toBe(true);
      expect(database.prepared.every((sql) => !sql.includes("hostile"))).toBe(true);
    } finally { database.close(); }
  });

  test("runs additive migrations sequentially and the second plan is empty", async () => {
    const database = new LocalD1();
    try {
      const first = await getMigrations(options(database));
      expect(await first.compileMigrations()).toContain('create table "probe"');
      await first.runMigrations();
      const second = await getMigrations(options(database));
      expect(await second.compileMigrations()).toBe(";");
      expect(database.batches.length).toBeGreaterThan(0);
      const introspection = database.batches.flat();
      expect(introspection.some((sql) => sql.startsWith("PRAGMA index_list("))).toBe(true);
      expect(introspection.some((sql) => sql.startsWith("PRAGMA index_info("))).toBe(true);
      expect(introspection.every((sql) =>
        sql === "SELECT * FROM pragma_table_info(?)" ||
        sql.startsWith("PRAGMA index_list(") ||
        sql.startsWith("PRAGMA index_info("),
      )).toBe(true);
    } finally { database.close(); }
  });

  test("refuses an unsafe required-column addition on populated D1 storage", async () => {
    const database = new LocalD1();
    try {
      database.exec('create table "probe" ("id" text not null primary key)');
      database.exec('insert into "probe" ("id") values (\'existing\')');
      await expect(getMigrations(options(database))).rejects.toThrow(
        'Cannot add required column "label" to populated table "probe"',
      );
    } finally { database.close(); }
  });
});
