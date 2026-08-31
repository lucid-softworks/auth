import { readFile } from "node:fs/promises";
import { afterAll, beforeEach, describe, expect, test } from "vitest";
import { mongodbAdapter } from "@better-auth/mongo-adapter";
import { MongoClient, ObjectId, UUID } from "mongodb";

const standaloneUri = process.env.MONGODB_ORACLE_STANDALONE_URI;
const replicaUri = process.env.MONGODB_ORACLE_REPLICA_SET_URI;
const suite = standaloneUri && replicaUri ? describe : describe.skip;
const standalone = standaloneUri ? new MongoClient(standaloneUri) : null;
const replica = replicaUri ? new MongoClient(replicaUri) : null;
const standaloneDb = standalone?.db("lucid_auth_mongodb_oracle_standalone");
const replicaDb = replica?.db("lucid_auth_mongodb_oracle_replica");
const adapterPackage = JSON.parse(
  await readFile(
    new URL("node_modules/@better-auth/mongo-adapter/package.json", import.meta.url),
    "utf8",
  ),
);
const driverPackage = JSON.parse(
  await readFile(new URL("node_modules/mongodb/package.json", import.meta.url), "utf8"),
);
const artifact = await readFile(
  new URL("node_modules/@better-auth/mongo-adapter/dist/index.mjs", import.meta.url),
  "utf8",
);

function options(generateId) {
  return {
    secret: "mongodb-adapter-oracle-secret-at-least-32-bytes",
    advanced: { database: { joins: true, ...(generateId === undefined ? {} : { generateId }) } },
    plugins: [
      {
        id: "mongodb-adapter-oracle",
        schema: {
          probe: {
            indexes: [{ fields: ["label"], unique: true }],
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

function adapter(db, client, transaction = true, generateId) {
  return mongodbAdapter(db, { client, transaction })(options(generateId));
}

async function reset(db) {
  await db.dropDatabase();
}

suite("@better-auth/mongo-adapter 1.7.1 oracle", () => {
  beforeEach(async () => {
    await Promise.all([reset(standaloneDb), reset(replicaDb)]);
  });
  afterAll(async () => {
    await Promise.all([standalone?.close(), replica?.close()]);
  });

  test("pins the driver, capabilities, coercion, regex, and lazy index artifact", () => {
    expect(adapterPackage.version).toBe("1.7.1");
    expect(driverPackage.version).toBe("7.1.0");
    expect(artifact).toContain('mapKeysTransformInput: { id: "_id" }');
    expect(artifact).toContain("supportsArrays: true");
    expect(artifact).toContain("supportsNumericIds: false");
    expect(artifact).toContain("input.slice(0, maxLength).replace");
    expect(artifact).toContain("indexSetupByDefinition.delete(indexDefinition)");
    expect(artifact).toContain("findOneAndDelete");
    expect(artifact).toContain("findOneAndUpdate");
  });

  test("standalone executes native values, predicates, joins, mutations, ids, and indexes", async () => {
    const store = adapter(standaloneDb, standalone, false);
    const happenedAt = new Date("2024-03-04T05:06:07.089Z");
    const group = await store.create({ model: "group", data: { name: "Example" } });
    const first = await store.create({
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
    await store.create({
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

    expect(first).toMatchObject({ enabled: true, happenedAt, tags: ["one", "two"], scores: [2, 3] });
    expect((await standaloneDb.collection("probe").findOne({ _id: new ObjectId(first.id) }))._id)
      .toBeInstanceOf(ObjectId);
    expect(
      await store.count({
        model: "probe",
        where: [{ field: "label", value: "ALP", operator: "starts_with", mode: "insensitive" }],
      }),
    ).toBe(2);
    expect(
      await store.findOne({ model: "group", where: [{ field: "id", value: group.id }], join: { probe: true } }),
    ).toMatchObject({ probe: [expect.objectContaining({ id: first.id })] });
    expect(
      await store.incrementOne({
        model: "probe",
        where: [{ field: "id", value: first.id }],
        increment: { counter: 3 },
        set: { label: "Updated" },
      }),
    ).toMatchObject({ counter: 7, label: "Updated" });
    expect(await store.consumeOne({ model: "probe", where: [{ field: "id", value: first.id }] }))
      .toMatchObject({ id: first.id, counter: 7 });
    expect(await store.consumeOne({ model: "probe", where: [{ field: "id", value: first.id }] }))
      .toBeNull();
    await expect(
      store.findOne({ model: "probe", where: [{ field: "id", value: 42 }] }),
    ).rejects.toMatchObject({ code: "INVALID_ID" });
    expect(await standaloneDb.collection("probe").listIndexes().toArray()).toContainEqual(
      expect.objectContaining({ key: { label: 1 }, unique: true }),
    );
  });

  test("UUID and callback strategies persist distinct BSON ID representations", async () => {
    const uuidStore = adapter(standaloneDb, standalone, false, "uuid");
    const uuidRow = await uuidStore.create({ model: "group", data: { name: "UUID" } });
    expect(UUID.isValid(uuidRow.id)).toBe(true);
    expect((await standaloneDb.collection("group").findOne({ name: "UUID" }))._id)
      .toBeInstanceOf(UUID);

    const callbackStore = adapter(standaloneDb, standalone, false, ({ model }) => `custom-${model}`);
    const callbackRow = await callbackStore.create({ model: "group", data: { name: "Callback" } });
    expect(callbackRow.id).toBe("custom-group");
    expect((await standaloneDb.collection("group").findOne({ name: "Callback" }))._id)
      .toBe("custom-group");
  });

  test("replica-set transaction commits success and aborts failure", async () => {
    const store = adapter(replicaDb, replica, true);
    await store.transaction(async (transaction) => {
      await transaction.create({ model: "group", data: { name: "commit" } });
    });
    expect(await store.count({ model: "group", where: [{ field: "name", value: "commit" }] }))
      .toBe(1);
    await expect(
      store.transaction(async (transaction) => {
        await transaction.create({ model: "group", data: { name: "rollback" } });
        throw new Error("rollback marker");
      }),
    ).rejects.toThrow("rollback marker");
    expect(await store.count({ model: "group", where: [{ field: "name", value: "rollback" }] }))
      .toBe(0);
  });
});
