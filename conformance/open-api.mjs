import assert from "node:assert/strict";
import { betterAuth } from "better-auth";
import * as clientPlugins from "better-auth/client/plugins";
import { openAPI } from "better-auth/plugins";

const secret = "O".repeat(32);
const schemaPath = "/api/auth/open-api/generate-schema";
const referencePath = "/api/auth/reference";
const optionalFixturePath = "/__conformance__/open-api/fixtures";

const coreMethods = {
  "/sign-in/social": ["post"],
  "/callback/{id}": ["get", "post"],
  "/get-session": ["get", "post"],
  "/sign-out": ["post"],
  "/sign-up/email": ["post"],
  "/sign-in/email": ["post"],
  "/reset-password": ["post"],
  "/verify-password": ["post"],
  "/verify-email": ["get"],
  "/send-verification-email": ["post"],
  "/change-email": ["post"],
  "/change-password": ["post"],
  "/update-session": ["post"],
  "/update-user": ["post"],
  "/delete-user": ["post"],
  "/request-password-reset": ["post"],
  "/reset-password/{token}": ["get"],
  "/list-sessions": ["get"],
  "/revoke-session": ["post"],
  "/revoke-sessions": ["post"],
  "/revoke-other-sessions": ["post"],
  "/link-social": ["post"],
  "/list-accounts": ["get"],
  "/delete-user/callback": ["get"],
  "/unlink-account": ["post"],
  "/refresh-token": ["post"],
  "/get-access-token": ["post"],
  "/account-info": ["get"],
  "/ok": ["get"],
  "/error": ["get"],
};

const standardDescriptions = {
  400: "Bad Request. Usually due to missing parameters, or invalid parameters.",
  401: "Unauthorized. Due to missing or invalid authentication.",
  403: "Forbidden. You do not have permission to access this resource or to perform this action.",
  404: "Not Found. The requested resource was not found.",
  429: "Too Many Requests. You have exceeded the rate limit. Try again later.",
  500: "Internal Server Error. This is a problem with the server that you cannot fix.",
};

function url(origin, path) {
  return new URL(path, `${origin}/`).href;
}

async function jsonResponse(response, label) {
  assert.equal(response.status, 200, `${label}: unexpected status`);
  assert.match(
    response.headers.get("content-type") ?? "",
    /^application\/json(?:;|$)/i,
    `${label}: unexpected content type`,
  );
  return response.json();
}

function operationCount(document) {
  return Object.values(document.paths).reduce(
    (count, path) => count + Object.keys(path).length,
    0,
  );
}

function jsonValue(value) {
  return JSON.parse(JSON.stringify(value));
}

function assertCoreInventory(document, exact) {
  const expectedPaths = Object.keys(coreMethods);
  if (exact) assert.deepEqual(Object.keys(document.paths), expectedPaths);
  for (const [path, methods] of Object.entries(coreMethods)) {
    assert.ok(document.paths[path], `OpenAPI path ${path} is missing`);
    assert.deepEqual(
      Object.keys(document.paths[path]).sort(),
      methods,
      `OpenAPI methods differ for ${path}`,
    );
  }
  if (exact) {
    assert.equal(expectedPaths.length, 30);
    assert.equal(operationCount(document), 32);
  }
}

function assertEnvelope(document, expectedServer) {
  assert.equal(document.openapi, "3.1.1");
  assert.deepEqual(document.info, {
    title: "Better Auth",
    description: "API Reference for your Better Auth Instance",
    version: "1.1.0",
  });
  assert.deepEqual(document.security, [
    { apiKeyCookie: [], bearerAuth: [] },
  ]);
  assert.deepEqual(document.servers, [{ url: expectedServer }]);
  assert.deepEqual(document.tags, [
    {
      name: "Default",
      description:
        "Default endpoints that are included with Better Auth by default. These endpoints are not part of any plugin.",
    },
  ]);
  assert.deepEqual(document.components.securitySchemes, {
    apiKeyCookie: {
      type: "apiKey",
      in: "cookie",
      name: "apiKeyCookie",
      description: "API Key authentication via cookie",
    },
    bearerAuth: {
      type: "http",
      scheme: "bearer",
      description: "Bearer token authentication",
    },
  });
  assert.equal("/open-api/generate-schema" in document.paths, false);
  assert.equal("/reference" in document.paths, false);
}

function assertRepresentativeMetadata(document) {
  const callback = document.paths["/callback/{id}"];
  assert.deepEqual(callback.get.parameters, [
    {
      name: "id",
      in: "path",
      required: true,
      schema: { type: "string" },
    },
  ]);
  assert.equal("requestBody" in callback.get, false);
  assert.equal(callback.post.requestBody.required, false);

  const getSession = document.paths["/get-session"];
  assert.equal(getSession.get.operationId, "getSession");
  assert.equal(getSession.post.operationId, "getSessionPost");
  assert.equal(getSession.get.description, "Get the current session");
  assert.deepEqual(getSession.get.security, [{ bearerAuth: [] }]);
  assert.deepEqual(
    getSession.get.responses["200"].content["application/json"].schema.type,
    ["object", "null"],
  );

  const signUp = document.paths["/sign-up/email"].post;
  assert.equal(signUp.operationId, "signUpWithEmailAndPassword");
  const signUpSchema = signUp.requestBody.content["application/json"].schema;
  assert.deepEqual(signUpSchema.required, ["name", "email", "password"]);
  assert.equal(signUpSchema.properties.password.type, "string");
  assert.equal(signUpSchema.properties.rememberMe.type, "boolean");

  for (const [status, description] of Object.entries(standardDescriptions)) {
    assert.equal(signUp.responses[status].description, description);
  }
  assert.deepEqual(
    signUp.responses["400"].content["application/json"].schema.required,
    ["message"],
  );
  assert.equal(
    "required" in
      signUp.responses["403"].content["application/json"].schema,
    false,
  );

  const schemas = document.components.schemas;
  assert.deepEqual(Object.keys(schemas), [
    "User",
    "Session",
    "Account",
    "Verification",
  ]);
  assert.deepEqual(schemas.User.properties.id, {
    type: "string",
    readOnly: true,
  });
  assert.deepEqual(schemas.User.properties.emailVerified, {
    type: "boolean",
    default: false,
    readOnly: true,
  });
  assert.deepEqual(schemas.User.properties.createdAt, {
    type: "string",
    format: "date-time",
  });
  assert.ok(schemas.Session.required.includes("userId"));
  assert.ok(schemas.Account.required.includes("providerId"));
  assert.ok(schemas.Verification.required.includes("expiresAt"));
}

function pluginConformance() {
  const plugin = openAPI();
  assert.deepEqual(Object.keys(plugin), ["id", "version", "endpoints", "options"]);
  assert.equal(plugin.id, "open-api");
  assert.equal(plugin.version, "1.7.2");
  assert.equal(plugin.options, undefined);
  assert.deepEqual(Object.keys(plugin.endpoints), [
    "generateOpenAPISchema",
    "openAPIReference",
  ]);
  assert.equal(plugin.endpoints.generateOpenAPISchema.path, "/open-api/generate-schema");
  assert.equal(plugin.endpoints.generateOpenAPISchema.options.method, "GET");
  assert.equal(plugin.endpoints.openAPIReference.path, "/reference");
  assert.equal(plugin.endpoints.openAPIReference.options.method, "GET");
  assert.deepEqual(plugin.endpoints.openAPIReference.options.metadata, {
    scope: "server",
  });
  for (const unsupported of [
    "$ERROR_CODES",
    "client",
    "cookies",
    "hooks",
    "migrations",
    "onRequest",
    "rateLimit",
    "schema",
  ]) {
    assert.equal(unsupported in plugin, false, `${unsupported} must not be advertised`);
  }
  assert.equal("openAPIClient" in clientPlugins, false);

  const custom = openAPI({ path: "/docs", theme: "moon", nonce: "oracle-nonce" });
  assert.equal(custom.endpoints.openAPIReference.path, "/docs");
  assert.deepEqual(custom.options, {
    path: "/docs",
    theme: "moon",
    nonce: "oracle-nonce",
  });
}

function createOracle(origin, options) {
  return betterAuth({
    baseURL: origin,
    secret,
    plugins: [openAPI(options)],
  });
}

async function oracleConformance(origin) {
  const auth = createOracle(origin);
  assert.equal(typeof auth.api.generateOpenAPISchema, "function");
  const direct = await auth.api.generateOpenAPISchema();
  assertEnvelope(direct, `${origin}/api/auth`);
  assertCoreInventory(direct, true);
  assertRepresentativeMetadata(direct);

  const response = await auth.handler(new Request(url(origin, schemaPath)));
  const endpoint = await jsonResponse(response, "Better Auth schema endpoint");
  const serialized = jsonValue(direct);
  assert.deepEqual(endpoint, serialized);

  const reference = await auth.handler(new Request(url(origin, referencePath)));
  assert.equal(reference.status, 200);
  assert.match(reference.headers.get("content-type") ?? "", /^text\/html(?:;|$)/i);
  assertScalarPage(await reference.text(), serialized);

  const custom = createOracle(origin, {
    path: "/docs",
    theme: "moon",
    nonce: "oracle-nonce",
  });
  const customReference = await custom.handler(
    new Request(url(origin, "/api/auth/docs")),
  );
  assert.equal(customReference.status, 200);
  assertScalarPage(
    await customReference.text(),
    jsonValue(await custom.api.generateOpenAPISchema()),
    { nonce: "oracle-nonce", theme: "moon" },
  );

  const disabled = createOracle(origin, { disableDefaultReference: true });
  const disabledReference = await disabled.handler(
    new Request(url(origin, referencePath)),
  );
  assert.equal(disabledReference.status, 404);
  assert.match(
    disabledReference.headers.get("content-type") ?? "",
    /^application\/json(?:;|$)/i,
  );
  assert.equal(await disabledReference.text(), "");
  assert.equal(
    (await disabled.handler(new Request(url(origin, schemaPath)))).status,
    200,
  );
  return serialized;
}

function extractEmbeddedDocument(html) {
  const match = html.match(
    /<script\s+id=["']api-reference["']\s+type=["']application\/json["']>([\s\S]*?)<\/script>/i,
  );
  assert.ok(match, "Scalar page does not embed the api-reference JSON script");
  return JSON.parse(match[1].trim());
}

function assertScalarPage(html, document, { nonce, theme = "default" } = {}) {
  assert.deepEqual(extractEmbeddedDocument(html), document);
  assert.match(html, /https:\/\/cdn\.jsdelivr\.net\/npm\/@scalar\/api-reference/);
  assert.match(html, /favicon:\s*"data:image\/svg\+xml;utf8,/);
  assert.ok(html.includes(`theme: "${theme}"`), `Scalar theme ${theme} is missing`);
  assert.match(html, /title:\s*"Better Auth API"/);
  assert.match(html, /description:\s*"API Reference for your Better Auth Instance"/);
  if (nonce !== undefined) {
    const escaped = nonce.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    assert.equal(
      [...html.matchAll(new RegExp(`nonce=["']${escaped}["']`, "g"))].length,
      2,
      "nonce must be attached to both executable Scalar scripts",
    );
  }
}

function assertSchemaContains(oracle, native) {
  for (const [name, oracleSchema] of Object.entries(oracle.components.schemas)) {
    const nativeSchema = native.components.schemas[name];
    assert.ok(nativeSchema, `native component ${name} is missing`);
    assert.equal(nativeSchema.type, oracleSchema.type);
    for (const [field, schema] of Object.entries(oracleSchema.properties)) {
      assert.deepEqual(nativeSchema.properties[field], schema, `${name}.${field} differs`);
    }
    for (const required of oracleSchema.required) {
      assert.ok(nativeSchema.required.includes(required), `${name}.${required} is not required`);
    }
  }
}

function assertOperationMatches(oracle, native, path, method) {
  const expected = oracle.paths[path][method];
  const actual = native.paths[path][method];
  for (const key of ["tags", "description", "operationId", "security", "parameters", "responses"]) {
    assert.deepEqual(actual[key], expected[key], `${method.toUpperCase()} ${path} ${key} differs`);
  }
  if (path === "/sign-up/email" || path === "/update-user") {
    const expectedBody = expected.requestBody?.content?.["application/json"]?.schema;
    const actualBody = actual.requestBody?.content?.["application/json"]?.schema;
    assert.ok(actualBody, `${method.toUpperCase()} ${path} request body is missing`);
    for (const [field, schema] of Object.entries(expectedBody?.properties ?? {})) {
      assert.deepEqual(actualBody.properties[field], schema, `${path}.${field} differs`);
    }
    for (const required of expectedBody?.required ?? []) {
      assert.ok(actualBody.required.includes(required), `${path}.${required} is not required`);
    }
  } else {
    assert.deepEqual(actual.requestBody, expected.requestBody, `${method.toUpperCase()} ${path} request body differs`);
  }
}

async function nativeDefaultConformance(origin, oracle) {
  const metadataResponse = await fetch(url(origin, "/__conformance__/plugins"));
  const plugins = await jsonResponse(metadataResponse, "native plugin metadata");
  const descriptor = plugins.find((plugin) => plugin.id === "open-api");
  assert.ok(descriptor, "native Open API plugin descriptor is missing");
  assert.equal(descriptor.version, "1.7.2");
  assert.equal(descriptor.client, null);
  assert.deepEqual(
    descriptor.endpoints.map(({ method, path }) => [method, path]),
    [
      ["GET", "/open-api/generate-schema"],
      ["GET", "/reference"],
    ],
  );
  for (const contribution of [
    "dependencies",
    "conflicts",
    "cookies",
    "rateLimits",
    "middleware",
  ]) {
    assert.deepEqual(descriptor[contribution], [], `${contribution} must be empty`);
  }

  const schemaResponse = await fetch(url(origin, schemaPath));
  const native = await jsonResponse(schemaResponse, "native schema endpoint");
  assertEnvelope(native, `${origin}/api/auth`);
  assertCoreInventory(native, false);
  assertSchemaContains(oracle, native);
  for (const [path, methods] of Object.entries(coreMethods)) {
    for (const method of methods) assertOperationMatches(oracle, native, path, method);
  }

  const referenceResponse = await fetch(url(origin, referencePath));
  assert.equal(referenceResponse.status, 200);
  assert.match(referenceResponse.headers.get("content-type") ?? "", /^text\/html(?:;|$)/i);
  assertScalarPage(await referenceResponse.text(), native);
  return native;
}

async function optionalNativeOptionsConformance(origin) {
  const response = await fetch(url(origin, optionalFixturePath));
  if (response.status === 404) return;
  const fixtures = await jsonResponse(response, "native Open API fixture manifest");

  if (fixtures.custom) {
    const schema = await jsonResponse(
      await fetch(url(origin, fixtures.custom.schemaPath)),
      "custom-path schema fixture",
    );
    const reference = await fetch(url(origin, fixtures.custom.referencePath));
    assert.equal(reference.status, 200);
    assertScalarPage(await reference.text(), schema);
  }
  if (fixtures.disabled) {
    await jsonResponse(
      await fetch(url(origin, fixtures.disabled.schemaPath)),
      "disabled-reference schema fixture",
    );
    const reference = await fetch(url(origin, fixtures.disabled.referencePath));
    assert.equal(reference.status, 404);
    assert.match(reference.headers.get("content-type") ?? "", /^application\/json(?:;|$)/i);
    assert.equal(await reference.text(), "");
  }
  if (fixtures.nonce) {
    const reference = await fetch(url(origin, fixtures.nonce.referencePath));
    assert.equal(reference.status, 200);
    const html = await reference.text();
    const schema = extractEmbeddedDocument(html);
    assertScalarPage(html, schema, { nonce: fixtures.nonce.value });
  }
  if (fixtures.theme) {
    const reference = await fetch(url(origin, fixtures.theme.referencePath));
    assert.equal(reference.status, 200);
    const html = await reference.text();
    const schema = extractEmbeddedDocument(html);
    assertScalarPage(html, schema, { theme: fixtures.theme.value });
  }
}

export async function openApiConformance(origin) {
  pluginConformance();
  const oracle = await oracleConformance(origin);
  await nativeDefaultConformance(origin, oracle);
  await optionalNativeOptionsConformance(origin);
  console.log("ok - Open API 1.7.2 oracle and native schema contract");
}
