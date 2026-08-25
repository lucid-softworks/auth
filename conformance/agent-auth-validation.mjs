import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { agentAuth } from "@better-auth/agent-auth";
import { betterAuth } from "better-auth";

const VALID_BODY = {
  register: { name: "agent" },
  updateAgent: { agent_id: "agent" },
  revokeAgent: {},
  revokeCapability: { agent_id: "agent", capabilities: ["files.read"] },
  rotateKey: { agent_id: "agent", public_key: {} },
  reactivateAgent: { agent_id: "agent" },
  requestCapability: { capabilities: ["files.read"] },
  approveCapability: { action: "approve" },
  executeCapability: { capability: "files.read" },
  batchExecuteCapability: { requests: [{ capability: "files.read" }] },
  introspect: { token: "token" },
  grantCapability: { agent_id: "agent", capabilities: ["files.read"] },
  createHost: {},
  enrollHost: { token: "token", public_key: {} },
  revokeHost: {},
  switchHostAccount: { host_id: "host" },
  updateHost: { host_id: "host" },
  rotateHostKey: { public_key: {} },
  cibaAuthorize: { login_hint: "agent@example.test" },
  deviceCode: { agent_id: "agent" },
  claimAgent: { agent_id: "agent" },
};

export async function agentAuthValidationContract() {
  const plugin = agentAuth();
  const results = [];
  await malformedJsonResults(plugin, results);
  await mediaTypeResults(plugin, results);
  await bodyValidationResults(plugin, results);
  await queryValidationResults(plugin, results);
  assert.equal(results.length, 164);
  assert.equal(
    digest(results),
    "245f43b2ec489ec2476560129f0ea9be00d69df0b52e30d33a8fd084e5e3fcb1",
    `Agent Auth validation contract changed:\n${JSON.stringify(results, null, 2)}`,
  );
}

async function mediaTypeResults(plugin, results) {
  const auth = betterAuth({
    baseURL: "http://agent-auth-validation.test",
    secret: "0123456789abcdef0123456789abcdef",
    plugins: [plugin],
  });
  for (const [name, endpoint] of Object.entries(plugin.endpoints)) {
    if (endpoint.options.method !== "POST") continue;
    const body = JSON.stringify(VALID_BODY[name] ?? {});
    for (const [validationCase, headers] of [
      ["missing-content-type", {}],
      ["text-content-type", { "content-type": "text/plain;charset=UTF-8" }],
    ]) {
      const response = await auth.handler(
        new Request(`http://agent-auth-validation.test/api/auth${endpoint.path}`, {
          method: "POST",
          headers,
          body: new TextEncoder().encode(body),
        }),
      );
      results.push({
        path: endpoint.path,
        case: validationCase,
        status: response.status,
        body: await response.json(),
      });
    }
  }
}

async function malformedJsonResults(plugin, results) {
  const auth = betterAuth({
    baseURL: "http://agent-auth-validation.test",
    secret: "0123456789abcdef0123456789abcdef",
    plugins: [plugin],
  });
  for (const endpoint of Object.values(plugin.endpoints)) {
    if (endpoint.options.method !== "POST") continue;
    const response = await auth.handler(
      new Request(`http://agent-auth-validation.test/api/auth${endpoint.path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{",
      }),
    );
    results.push({
      path: endpoint.path,
      case: "malformed-json",
      status: response.status,
      body: await response.json(),
    });
  }
}

async function bodyValidationResults(plugin, results) {
  for (const [name, endpoint] of Object.entries(plugin.endpoints)) {
    const schema = endpoint.options.body;
    const shape = objectShape(schema);
    if (!shape) continue;
    if (schema._zod.def.type !== "optional") {
      results.push(await rejected(endpoint, "missing-body", {}));
    }
    const baseline = VALID_BODY[name];
    assert.ok(baseline, `missing validation baseline for ${name}`);
    for (const [field, fieldSchema] of Object.entries(shape)) {
      const body = { ...baseline, [field]: wrongValue(fieldSchema) };
      results.push(await rejected(endpoint, `wrong-body-${field}`, { body }));
    }
  }
}

async function queryValidationResults(plugin, results) {
  for (const endpoint of Object.values(plugin.endpoints)) {
    const schema = endpoint.options.query;
    const shape = objectShape(schema);
    if (!shape) continue;
    const required = Object.entries(shape).filter(([, field]) => !field.safeParse(undefined).success);
    if (required.length > 0) {
      results.push(await rejected(endpoint, "missing-query", { query: {} }));
    }
    const baseline = Object.fromEntries(required.map(([field]) => [field, "value"]));
    for (const [field, fieldSchema] of Object.entries(shape)) {
      const query = { ...baseline, [field]: wrongValue(fieldSchema) };
      results.push(await rejected(endpoint, `wrong-query-${field}`, { query }));
    }
  }
}

async function rejected(endpoint, validationCase, input) {
  try {
    await endpoint({ asResponse: true, ...input });
  } catch (error) {
    assert.equal(error.statusCode, 400);
    assert.deepEqual(Object.keys(error.body), ["message", "code"]);
    return {
      path: endpoint.path,
      case: validationCase,
      status: error.statusCode,
      body: error.body,
    };
  }
  assert.fail(`${endpoint.path} ${validationCase} was not rejected`);
}

function objectShape(schema) {
  if (!schema) return null;
  const object = schema._zod.def.type === "optional" ? schema._zod.def.innerType : schema;
  return object._zod.def.type === "object" ? object.shape : null;
}

function wrongValue(schema) {
  const value = schema._zod.def.type === "optional" ? schema._zod.def.innerType : schema;
  switch (value._zod.def.type) {
    case "string":
    case "boolean":
      return 7;
    case "number":
      return "not-a-number";
    case "array":
    case "record":
      return "wrong";
    case "enum":
      return "not-an-option";
    default:
      throw new Error(`unsupported validation type: ${value._zod.def.type}`);
  }
}

function digest(value) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
