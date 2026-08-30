import { readFile } from "node:fs/promises";
import { describe, expect, test } from "vitest";
import * as scimModule from "@better-auth/scim";
import { packageJson, packageLock } from "./infra-email.helpers.mjs";

const staticOptions = {
  connections: [],
  authentication: { verifyBearerToken: () => null },
};

const endpointInventory = [
  ["createSCIMManagedConnection", null, "POST", true],
  ["listSCIMManagedConnections", null, "POST", true],
  ["getSCIMManagedConnection", null, "POST", true],
  ["rotateSCIMManagedCredential", null, "POST", true],
  ["revokeSCIMManagedCredential", null, "POST", true],
  ["listSCIMManagedConnectionEvents", null, "POST", true],
  ["decommissionSCIMManagedConnection", null, "POST", true],
  ["decommissionSCIMConnection", null, "POST", true],
  ["reconcileSCIMProjection", null, "POST", true],
  ["createSCIMGroup", "/scim/v2/Groups", "POST", false],
  ["deleteSCIMGroup", "/scim/v2/Groups/:groupId", "DELETE", false],
  ["getSCIMGroup", "/scim/v2/Groups/:groupId", "GET", false],
  ["listSCIMGroups", "/scim/v2/Groups", "GET", false],
  ["patchSCIMGroup", "/scim/v2/Groups/:groupId", "PATCH", false],
  ["replaceSCIMGroup", "/scim/v2/Groups/:groupId", "PUT", false],
  ["createSCIMUser", "/scim/v2/Users", "POST", false],
  ["deleteSCIMUser", "/scim/v2/Users/:userId", "DELETE", false],
  ["getSCIMUser", "/scim/v2/Users/:userId", "GET", false],
  ["listSCIMUsers", "/scim/v2/Users", "GET", false],
  ["patchSCIMUser", "/scim/v2/Users/:userId", "PATCH", false],
  ["replaceSCIMUser", "/scim/v2/Users/:userId", "PUT", false],
  ["getSCIMServiceProviderConfig", "/scim/v2/ServiceProviderConfig", "GET", false],
  ["getSCIMSchemas", "/scim/v2/Schemas", "GET", false],
  ["getSCIMSchema", "/scim/v2/Schemas/:schemaId", "GET", false],
  ["getSCIMResourceTypes", "/scim/v2/ResourceTypes", "GET", false],
  ["getSCIMResourceType", "/scim/v2/ResourceTypes/:resourceTypeId", "GET", false],
];

const coreModels = {
  scimConnectionBinding: 13,
  scimIdentityTombstone: 7,
  scimSubject: 5,
  scimUser: 21,
  scimProjectionGrant: 11,
  scimGroup: 10,
  scimGroupMember: 5,
};

describe("@better-auth/scim@1.7.1 artifact oracle", () => {
  test("pins the immutable package, exports, and missing subpaths", async () => {
    const pkg = await packageJson("@better-auth/scim");
    const locked = (await packageLock()).packages["node_modules/@better-auth/scim"];
    expect(pkg.version).toBe("1.7.1");
    expect(pkg.exports).toEqual({
      ".": {
        "dev-source": "./src/index.ts",
        types: "./dist/index.d.mts",
        default: "./dist/index.mjs",
      },
    });
    expect(locked.resolved).toBe(
      "https://registry.npmjs.org/@better-auth/scim/-/scim-1.7.1.tgz",
    );
    expect(locked.integrity).toBe(
      "sha512-bpOPVnYYTUROAJZU0ViL1jXHXoUulVn0Gl3HLN8Epj00Yqob4+rhf3XqVmc/2bi3TY40rmZIlsf1mXQhRdFd1w==",
    );
    expect("715077319aeba4a35f114f7dfc2a8e0523aa9f6f").toHaveLength(40);
    expect(Object.keys(scimModule).sort()).toEqual([
      "SCIM_MANAGED_CREATION_REQUEST_ID_CONFLICT",
      "acquireActiveSCIMUserLink",
      "scim",
    ]);
  });

  test("publishes the exact descriptor and endpoint inventory", () => {
    const plugin = scimModule.scim(staticOptions);
    expect({ id: plugin.id, version: plugin.version }).toEqual({ id: "scim", version: "1.7.1" });
    expect(Object.entries(plugin.endpoints).map(([name, endpoint]) => [
      name,
      endpoint.path ?? null,
      endpoint.options.method,
      endpoint.options.metadata?.SERVER_ONLY === true,
    ])).toEqual(endpointInventory);
    expect(endpointInventory.filter(([, path]) => path !== null)).toHaveLength(17);
    expect(plugin.hooks.after).toHaveLength(1);
  });

  test("contributes seven core models and three conditional managed models", () => {
    const plugin = scimModule.scim(staticOptions);
    expect(Object.fromEntries(Object.entries(plugin.schema).map(([name, schema]) => [
      name,
      Object.keys(schema.fields).length,
    ]))).toEqual(coreModels);

    const managed = scimModule.scim({
      connections: [],
      managedConnections: { credentialHashSecret: "x".repeat(32) },
    });
    expect(Object.keys(managed.schema).slice(0, 3)).toEqual([
      "scimManagedConnection",
      "scimManagedCredential",
      "scimManagedConnectionEvent",
    ]);
    expect(Object.keys(managed.schema)).toHaveLength(10);
  });

  test("pins transaction, media, authentication, and managed secret boundaries", async () => {
    const source = await readFile(
      new URL("node_modules/@better-auth/scim/dist/index.mjs", import.meta.url),
      "utf8",
    );
    for (const fragment of [
      'const SCIM_MEDIA_TYPE = "application/scim+json"',
      'const SCIM_MANAGED_CONNECTION_ID_PREFIX = "ba_scim_connection_"',
      'const SCIM_MANAGED_CREDENTIAL_ID_PREFIX = "ba_scim_credential_"',
      'const SCIM_IDENTITY_TRANSACTION_ATTEMPTS = 3',
      'const SCIM_GROUP_TRANSACTION_ATTEMPTS = 3',
      'const SCIM_PROJECTION_BATCH_SIZE = 50',
      'const SCIM_DECOMMISSION_LEASE_DURATION_MS = 300 * 1e3',
      'const SCIM_MAX_GROUP_MEMBERS = 1e3',
      'const count = Math.min(Math.max(parsedCount.value ?? 100, 0), 100)',
      'Bearer realm=\\"SCIM\\"',
      'SCIM requests must use application/scim+json or application/json',
      'The scim plugin requires a database adapter with native transaction support.',
    ]) expect(source).toContain(fragment);
  });
});
