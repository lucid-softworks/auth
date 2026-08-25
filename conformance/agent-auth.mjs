import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import {
  AGENT_AUTH_ERROR_CODES,
  agentAuth,
  agentError,
  asyncResult,
  streamResult,
  verifyAgentRequest,
} from "@better-auth/agent-auth";
import {
  AGENT_AUTH_ERROR_CODES as CLIENT_ERROR_CODES,
  agentAuthChallenge,
  agentAuthClient,
} from "@better-auth/agent-auth/client";
import {
  createFromOpenAPI,
  createOpenAPIHandler,
  fromOpenAPI,
} from "@better-auth/agent-auth/openapi";
import {
  AgentAuthClient,
  MemoryStorage,
  discoverProvider,
  generateKeypair,
  signAgentJWT,
  signHostJWT,
} from "@auth/agent";
import { decodeJwt, decodeProtectedHeader } from "jose";
import { agentAuthValidationContract } from "./agent-auth-validation.mjs";

const ENDPOINTS = {
  getAgentConfiguration: ["/agent-configuration", "GET", [], []],
  register: [
    "/agent/register",
    "POST",
    [
      "name",
      "capabilities",
      "reason",
      "mode",
      "preferred_method",
      "host_name",
      "login_hint",
      "binding_message",
      "force_approval",
    ],
    [],
  ],
  listAgents: ["/agent/list", "GET", [], []],
  getAgent: ["/agent/get", "GET", [], ["agent_id"]],
  updateAgent: ["/agent/update", "POST", ["agent_id", "name", "metadata"], []],
  revokeAgent: ["/agent/revoke", "POST", ["agent_id"], []],
  revokeCapability: [
    "/agent/revoke-capability",
    "POST",
    ["agent_id", "capabilities"],
    [],
  ],
  rotateKey: ["/agent/rotate-key", "POST", ["agent_id", "public_key"], []],
  reactivateAgent: ["/agent/reactivate", "POST", ["agent_id"], []],
  getAgentSession: ["/agent/session", "GET", [], []],
  cleanupAgents: ["/agent/cleanup", "POST", [], []],
  requestCapability: [
    "/agent/request-capability",
    "POST",
    ["capabilities", "reason", "preferred_method", "login_hint", "binding_message"],
    [],
  ],
  approveCapability: [
    "/agent/approve-capability",
    "POST",
    [
      "agent_id",
      "approval_id",
      "user_code",
      "action",
      "capabilities",
      "ttl",
      "reason",
      "webauthn_response",
    ],
    [],
  ],
  listCapabilities: ["/capability/list", "GET", [], []],
  describeCapability: ["/capability/describe", "GET", [], ["name"]],
  executeCapability: [
    "/capability/execute",
    "POST",
    ["capability", "arguments"],
    [],
  ],
  batchExecuteCapability: [
    "/capability/batch-execute",
    "POST",
    ["requests"],
    [],
  ],
  agentStatus: ["/agent/status", "GET", [], []],
  introspect: ["/agent/introspect", "POST", ["token"], []],
  grantCapability: [
    "/agent/grant-capability",
    "POST",
    ["agent_id", "capabilities", "ttl"],
    [],
  ],
  createHost: [
    "/host/create",
    "POST",
    ["name", "public_key", "jwks_url", "default_capabilities"],
    [],
  ],
  enrollHost: ["/host/enroll", "POST", ["token", "public_key", "name"], []],
  listHosts: ["/host/list", "GET", [], []],
  getHost: ["/host/get", "GET", [], ["host_id"]],
  revokeHost: ["/host/revoke", "POST", [], []],
  switchHostAccount: ["/host/switch-account", "POST", ["host_id"], []],
  updateHost: [
    "/host/update",
    "POST",
    ["host_id", "name", "public_key", "jwks_url", "default_capabilities"],
    [],
  ],
  rotateHostKey: ["/host/rotate-key", "POST", ["public_key"], []],
  cibaAuthorize: [
    "/agent/ciba/authorize",
    "POST",
    ["login_hint", "capabilities", "binding_message", "agent_id"],
    [],
  ],
  cibaPending: ["/agent/ciba/pending", "GET", [], []],
  deviceCode: ["/agent/device/code", "POST", ["agent_id"], []],
  claimAgent: [
    "/agent/claim",
    "POST",
    ["agent_id", "preferred_method", "login_hint", "binding_message"],
    [],
  ],
};

const CLIENT_PATH_METHODS = {
  "/agent-configuration": "GET",
  "/capability/list": "GET",
  "/capability/describe": "GET",
  "/capability/execute": "POST",
  "/agent/list": "GET",
  "/agent/get": "GET",
  "/agent/status": "GET",
  "/agent/session": "GET",
  "/host/list": "GET",
  "/host/get": "GET",
  "/agent/ciba/pending": "GET",
  "/agent/register": "POST",
  "/agent/update": "POST",
  "/agent/revoke": "POST",
  "/agent/rotate-key": "POST",
  "/agent/reactivate": "POST",
  "/agent/cleanup": "POST",
  "/agent/request-capability": "POST",
  "/agent/approve-capability": "POST",
  "/agent/introspect": "POST",
  "/agent/grant-capability": "POST",
  "/agent/revoke-capability": "POST",
  "/host/create": "POST",
  "/host/revoke": "POST",
  "/host/update": "POST",
  "/host/rotate-key": "POST",
  "/host/enroll": "POST",
  "/host/switch-account": "POST",
  "/agent/ciba/authorize": "POST",
  "/agent/device/code": "POST",
};

const ERROR_CODES = {
  INVALID_REQUEST: "invalid_request",
  INVALID_JWT: "invalid_jwt",
  AGENT_REVOKED: "agent_revoked",
  GRANT_REVOKED: "grant_revoked",
  AGENT_EXPIRED: "agent_expired",
  ABSOLUTE_LIFETIME_EXCEEDED: "absolute_lifetime_exceeded",
  AGENT_PENDING: "agent_pending",
  AGENT_REJECTED: "agent_rejected",
  AGENT_CLAIMED: "agent_claimed",
  AGENT_NOT_EXPIRED: "agent_not_expired",
  HOST_REVOKED: "host_revoked",
  HOST_PENDING: "host_pending",
  UNAUTHORIZED: "unauthorized",
  RATE_LIMITED: "rate_limited",
  INTERNAL_ERROR: "internal_error",
  UNSUPPORTED_MODE: "unsupported_mode",
  UNSUPPORTED_ALGORITHM: "unsupported_algorithm",
  INVALID_CAPABILITIES: "invalid_capabilities",
  AGENT_EXISTS: "agent_exists",
  ALREADY_GRANTED: "already_granted",
  CAPABILITY_NOT_GRANTED: "capability_not_granted",
  LIMIT_EXCEEDED: "limit_exceeded",
  CAPABILITY_BLOCKED: "capability_blocked",
  AGENT_NOT_FOUND: "agent_not_found",
  HOST_NOT_FOUND: "host_not_found",
  UNAUTHORIZED_SESSION: "unauthorized",
  INVALID_PUBLIC_KEY: "invalid_public_key",
  JWT_REPLAY: "jti_replay",
  REQUEST_BINDING_MISMATCH: "request_binding_mismatch",
  HOST_EXPIRED: "host_expired",
  HOST_ALREADY_LINKED: "host_already_linked",
  HOST_NOT_PENDING_ENROLLMENT: "host_not_pending_enrollment",
  DYNAMIC_HOST_REGISTRATION_DISABLED: "dynamic_host_registration_disabled",
  ENROLLMENT_TOKEN_INVALID: "enrollment_token_invalid",
  ENROLLMENT_TOKEN_EXPIRED: "enrollment_token_expired",
  CAPABILITY_REQUEST_NOT_FOUND: "capability_request_not_found",
  CAPABILITY_REQUEST_ALREADY_RESOLVED: "capability_request_already_resolved",
  CAPABILITY_REQUEST_OWNER_MISMATCH: "capability_request_owner_mismatch",
  FRESH_SESSION_REQUIRED: "fresh_session_required",
  CAPABILITY_DENIED: "capability_denied",
  AGENT_LIMIT_REACHED: "agent_limit_reached",
  AUTONOMOUS_OWNER_REQUIRED: "autonomous_owner_required",
  CIBA_NOT_FOUND: "ciba_not_found",
  CIBA_EXPIRED: "ciba_expired",
  CIBA_ALREADY_RESOLVED: "ciba_already_resolved",
  CIBA_SLOW_DOWN: "slow_down",
  UNKNOWN_CAPABILITIES: "unknown_capabilities",
  CAPABILITY_NOT_FOUND: "capability_not_found",
  AUTH_REQUIRED_FOR_CAPABILITIES: "authentication_required",
  CONSTRAINT_VIOLATED: "constraint_violated",
  EXECUTE_NOT_CONFIGURED: "execute_not_configured",
  UNKNOWN_CONSTRAINT_OPERATOR: "unknown_constraint_operator",
  INVALID_USER_CODE: "invalid_user_code",
  APPROVAL_EXPIRED: "approval_expired",
  WEBAUTHN_NOT_ENROLLED: "webauthn_not_enrolled",
  WEBAUTHN_REQUIRED: "webauthn_required",
  WEBAUTHN_VERIFICATION_FAILED: "webauthn_verification_failed",
};

const SCHEMA_FIELDS = {
  agentHost: [
    "name",
    "userId",
    "defaultCapabilities",
    "publicKey",
    "kid",
    "jwksUrl",
    "enrollmentTokenHash",
    "enrollmentTokenExpiresAt",
    "status",
    "activatedAt",
    "expiresAt",
    "lastUsedAt",
    "createdAt",
    "updatedAt",
  ],
  agent: [
    "name",
    "userId",
    "hostId",
    "status",
    "mode",
    "publicKey",
    "kid",
    "jwksUrl",
    "lastUsedAt",
    "activatedAt",
    "expiresAt",
    "metadata",
    "createdAt",
    "updatedAt",
  ],
  agentCapabilityGrant: [
    "agentId",
    "capability",
    "deniedBy",
    "grantedBy",
    "expiresAt",
    "createdAt",
    "updatedAt",
    "status",
    "reason",
    "constraints",
  ],
  approvalRequest: [
    "method",
    "agentId",
    "hostId",
    "userId",
    "capabilities",
    "status",
    "userCodeHash",
    "loginHint",
    "bindingMessage",
    "clientNotificationToken",
    "clientNotificationEndpoint",
    "deliveryMode",
    "interval",
    "lastPolledAt",
    "expiresAt",
    "createdAt",
    "updatedAt",
  ],
};

export async function agentAuthConformance() {
  await exportsContract();
  descriptorContract();
  schemaContract();
  rateLimitContract();
  await discoveryContract();
  await openApiContract();
  await helperAndSdkContract();
  await agentAuthValidationContract();
  console.log("ok - Agent Auth 0.6.2 upstream server and SDK contract");
}

async function exportsContract() {
  const serverPackage = JSON.parse(
    await readFile(
      new URL("node_modules/@better-auth/agent-auth/package.json", import.meta.url),
    ),
  );
  const sdkPackage = JSON.parse(
    await readFile(new URL("node_modules/@auth/agent/package.json", import.meta.url)),
  );
  const serverSource = await readFile(
    new URL("node_modules/@better-auth/agent-auth/dist/index.js", import.meta.url),
    "utf8",
  );
  assert.equal(serverPackage.version, "0.6.2");
  assert.equal(sdkPackage.version, "0.6.2");
  assert.deepEqual(Object.keys(serverPackage.exports), [".", "./client", "./openapi"]);
  assert.deepEqual(Object.keys(await import("@better-auth/agent-auth")).sort(), [
    "AGENT_AUTH_ERROR_CODES",
    "agentAuth",
    "agentError",
    "asyncResult",
    "streamResult",
    "verifyAgentRequest",
  ]);
  assert.deepEqual(Object.keys(await import("@better-auth/agent-auth/client")).sort(), [
    "AGENT_AUTH_ERROR_CODES",
    "agentAuthChallenge",
    "agentAuthClient",
    "agentError",
  ]);
  assert.deepEqual(Object.keys(await import("@better-auth/agent-auth/openapi")).sort(), [
    "createFromOpenAPI",
    "createOpenAPIHandler",
    "fromOpenAPI",
  ]);
  assert.deepEqual(Object.keys(await import("@auth/agent")).sort(), [
    "AgentAuthClient",
    "AgentAuthSDKError",
    "KVStorage",
    "MemoryStorage",
    "SERVER_INSTRUCTIONS",
    "detectHostName",
    "detectTool",
    "discoverProvider",
    "filterTools",
    "generateKeypair",
    "getAgentAuthTools",
    "matchQuery",
    "matchQueryScored",
    "signAgentJWT",
    "signHostJWT",
    "toAISDKTools",
    "toAnthropicTools",
    "toOpenAITools",
  ]);

  for (const fragment of [
    'allowedKeyAlgorithms: options?.allowedKeyAlgorithms ?? ["Ed25519"]',
    'jwtFormat: options?.jwtFormat ?? "simple"',
    "jwtMaxAge: options?.jwtMaxAge ?? 60",
    "agentSessionTTL: options?.agentSessionTTL ?? 3600",
    "agentMaxLifetime: options?.agentMaxLifetime ?? 86400",
    "maxAgentsPerUser: options?.maxAgentsPerUser ?? 25",
    "absoluteLifetime: options?.absoluteLifetime ?? 0",
    "freshSessionWindow: options?.freshSessionWindow ?? 300",
    "blockedCapabilities: options?.blockedCapabilities ?? []",
    "allowDynamicHostRegistration: options?.allowDynamicHostRegistration ?? false",
    "defaultHostCapabilities: options?.defaultHostCapabilities ?? []",
    'modes: options?.modes ?? ["delegated", "autonomous"]',
    'deviceAuthorizationPage: options?.deviceAuthorizationPage ?? "/device/capabilities"',
    'approvalMethods: options?.approvalMethods ?? ["ciba", "device_authorization"]',
    'jtiCacheStorage: options?.jtiCacheStorage ?? "memory"',
    'jwksCacheStorage: options?.jwksCacheStorage ?? "memory"',
    "dangerouslySkipJtiCheck: options?.dangerouslySkipJtiCheck ?? false",
    "trustProxy: options?.trustProxy ?? false",
    "const enabled = options?.proofOfPresence?.enabled ?? false",
  ]) {
    assert.ok(serverSource.includes(fragment), `missing upstream default: ${fragment}`);
  }
}

function descriptorContract() {
  const options = { providerName: "Oracle" };
  const plugin = agentAuth(options);
  assert.equal(plugin.id, "agent-auth");
  assert.equal(plugin.options, options);
  assert.equal(plugin.$ERROR_CODES, AGENT_AUTH_ERROR_CODES);
  assert.equal(plugin.hooks.before.length, 1);
  assert.equal(typeof plugin.init, "function");

  assert.deepEqual(
    Object.fromEntries(
      Object.entries(plugin.endpoints).map(([name, endpoint]) => [
        name,
        [
          endpoint.path,
          endpoint.options.method,
          Object.keys(endpoint.options.body?.shape ?? {}),
          Object.keys(endpoint.options.query?.shape ?? {}),
        ],
      ]),
    ),
    ENDPOINTS,
  );

  const client = agentAuthClient();
  assert.equal(client.id, "agent-auth");
  assert.deepEqual(client.pathMethods, CLIENT_PATH_METHODS);
  assert.equal(client.$ERROR_CODES, CLIENT_ERROR_CODES);
  assert.equal("/agent/claim" in client.pathMethods, false);
  assert.equal("/capability/batch-execute" in client.pathMethods, false);
}

function schemaContract() {
  const schema = agentAuth().schema;
  assert.deepEqual(Object.keys(schema), Object.keys(SCHEMA_FIELDS));
  for (const [model, fields] of Object.entries(SCHEMA_FIELDS)) {
    assert.deepEqual(Object.keys(schema[model].fields), fields);
  }
  const normalized = Object.fromEntries(
    Object.entries(schema).map(([model, value]) => [
      model,
      Object.fromEntries(
        Object.entries(value.fields).map(([field, definition]) => [
          field,
          {
            type: definition.type,
            required: definition.required,
            input: definition.input,
            index: definition.index ?? false,
            defaultValue: definition.defaultValue ?? null,
            references: definition.references ?? null,
            transform: definition.transform ? Object.keys(definition.transform) : [],
          },
        ]),
      ),
    ]),
  );
  assert.equal(
    digest(normalized),
    "e165978e4eaa01b125cde801e130cb63adf786ba9bb57d98faca85fffee54bc0",
  );

  assert.deepEqual(schema.agent.fields.hostId.references, {
    model: "agentHost",
    field: "id",
    onDelete: "cascade",
  });
  assert.deepEqual(schema.agentCapabilityGrant.fields.agentId.references, {
    model: "agent",
    field: "id",
    onDelete: "cascade",
  });
  for (const model of ["agentHost", "agent", "agentCapabilityGrant", "approvalRequest"]) {
    assert.equal(schema[model].fields.createdAt.type, "date");
    assert.equal(schema[model].fields.createdAt.required, true);
    assert.equal(schema[model].fields.updatedAt.type, "date");
    assert.equal(schema[model].fields.updatedAt.required, true);
  }
  assert.equal(schema.agentHost.fields.status.defaultValue, "active");
  assert.equal(schema.agent.fields.status.defaultValue, "active");
  assert.equal(schema.agent.fields.mode.defaultValue, "delegated");
  assert.equal(schema.agentCapabilityGrant.fields.status.defaultValue, "active");
  assert.equal(schema.approvalRequest.fields.status.defaultValue, "pending");

  const defaults = schema.agentHost.fields.defaultCapabilities.transform;
  assert.equal(defaults.input(["mail.read"]), '["mail.read"]');
  assert.deepEqual(defaults.output('["mail.read"]'), ["mail.read"]);
  assert.deepEqual(defaults.output(null), []);
  const metadata = schema.agent.fields.metadata.transform;
  assert.equal(metadata.input({ owner: "oracle" }), '{"owner":"oracle"}');
  assert.deepEqual(metadata.output('{"owner":"oracle"}'), { owner: "oracle" });
  assert.equal(metadata.output(null), null);
  const constraints = schema.agentCapabilityGrant.fields.constraints.transform;
  assert.equal(constraints.input({ limit: { max: 5 } }), '{"limit":{"max":5}}');
  assert.deepEqual(constraints.output('{"limit":{"max":5}}'), {
    limit: { max: 5 },
  });
}

function rateLimitContract() {
  const paths = [
    "/agent/register",
    "/agent/rotate-key",
    "/agent/cleanup",
    "/agent/approve-capability",
    "/agent/ciba/authorize",
    "/agent/status",
    "/agent/ciba/pending",
    "/agent/other",
    "/capability/execute",
    "/host/create",
  ];
  assert.deepEqual(
    agentAuth().rateLimit.map((rule) => ({
      window: rule.window,
      max: rule.max,
      paths: paths.filter((path) => rule.pathMatcher(path)),
    })),
    [
      { window: 60, max: 10, paths: ["/agent/register"] },
      { window: 60, max: 5, paths: ["/agent/rotate-key", "/agent/cleanup"] },
      { window: 60, max: 5, paths: ["/agent/approve-capability"] },
      { window: 60, max: 5, paths: ["/agent/ciba/authorize"] },
      { window: 60, max: 300, paths: ["/agent/status", "/agent/ciba/pending"] },
      {
        window: 60,
        max: 60,
        paths: [
          "/agent/register",
          "/agent/rotate-key",
          "/agent/cleanup",
          "/agent/approve-capability",
          "/agent/ciba/authorize",
          "/agent/status",
          "/agent/ciba/pending",
          "/agent/other",
          "/capability/execute",
        ],
      },
    ],
  );

  const overridden = agentAuth({
    rateLimit: {
      "/agent/register": { window: 7, max: 8 },
      "/agent/rotate-key": { window: 9, max: 10 },
      "/agent/status": { window: 11, max: 12 },
    },
  }).rateLimit;
  assert.deepEqual(
    overridden.slice(0, 2).map(({ window, max }) => ({ window, max })),
    [
      { window: 7, max: 8 },
      { window: 9, max: 10 },
    ],
  );
  assert.deepEqual(
    { window: overridden[4].window, max: overridden[4].max },
    { window: 11, max: 12 },
  );
}

async function discoveryContract() {
  const defaults = agentAuth();
  assert.equal(defaults.options, undefined);
  const response = await defaults.endpoints.getAgentConfiguration({
    context: { baseURL: "https://provider.example/api/auth/" },
    asResponse: true,
  });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "public, max-age=3600");
  assert.equal(response.headers.get("content-type"), "application/json");
  assert.deepEqual(await response.json(), discoveryDocument());

  const configured = agentAuth({
    providerName: "Configured provider",
    providerDescription: "Configured description",
    allowedKeyAlgorithms: ["P-256"],
    modes: ["delegated"],
    approvalMethods: ["ciba"],
    jwksUri: "https://provider.example/jwks.json",
  });
  const configuredResponse = await configured.endpoints.getAgentConfiguration({
    context: { baseURL: "https://provider.example/custom/" },
    asResponse: true,
  });
  assert.deepEqual(await configuredResponse.json(), {
    ...discoveryDocument("https://provider.example/custom"),
    provider_name: "Configured provider",
    description: "Configured description",
    algorithms: ["P-256"],
    modes: ["delegated"],
    approval_methods: ["ciba"],
    jwks_uri: "https://provider.example/jwks.json",
  });
}

function discoveryDocument(issuer = "https://provider.example/api/auth") {
  return {
    version: "1.0-draft",
    provider_name: "agent-auth",
    description: "Agent Auth enabled service",
    issuer,
    default_location: `${issuer}/capability/execute`,
    algorithms: ["Ed25519"],
    modes: ["delegated", "autonomous"],
    approval_methods: ["ciba", "device_authorization"],
    endpoints: {
      register: `${issuer}/agent/register`,
      capabilities: `${issuer}/capability/list`,
      describe_capability: `${issuer}/capability/describe`,
      execute: `${issuer}/capability/execute`,
      request_capability: `${issuer}/agent/request-capability`,
      status: `${issuer}/agent/status`,
      reactivate: `${issuer}/agent/reactivate`,
      revoke: `${issuer}/agent/revoke`,
      revoke_host: `${issuer}/host/revoke`,
      rotate_key: `${issuer}/agent/rotate-key`,
      rotate_host_key: `${issuer}/host/rotate-key`,
      introspect: `${issuer}/agent/introspect`,
    },
  };
}

async function openApiContract() {
  const spec = {
    info: {
      title: "Message API",
      description: "Read and create messages",
      version: "1.0.0",
    },
    paths: {
      "/messages/{id}": {
        parameters: [
          {
            name: "id",
            in: "path",
            required: true,
            description: "Message identifier",
            schema: { type: "string" },
          },
        ],
        get: {
          operationId: "messages.get",
          summary: "Get a message",
          parameters: [
            { name: "verbose", in: "query", schema: { type: "boolean" } },
            { name: "x-tenant", in: "header", required: true },
          ],
          responses: {
            200: {
              content: {
                "application/json": {
                  schema: { type: "object", properties: { id: { type: "string" } } },
                },
              },
            },
          },
        },
        post: {
          operationId: "messages.create",
          description: "Create a message",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: { subject: { type: "string" } },
                  required: ["subject"],
                },
              },
            },
          },
          responses: { 201: { description: "Created" } },
        },
      },
    },
  };
  const capabilities = fromOpenAPI(spec);
  assert.deepEqual(
    capabilities.map(({ name, description }) => ({ name, description })),
    [
      { name: "messages.get", description: "Get a message" },
      { name: "messages.create", description: "Create a message" },
    ],
  );
  assert.deepEqual(capabilities[0].input.required, ["id", "x-tenant"]);
  assert.deepEqual(Object.keys(capabilities[0].input.properties), [
    "id",
    "verbose",
    "x-tenant",
  ]);
  assert.deepEqual(capabilities[0].output, {
    type: "object",
    properties: { id: { type: "string" } },
  });
  assert.deepEqual(capabilities[1].input.required, ["id", "subject"]);

  const requests = [];
  const handler = createOpenAPIHandler(spec, {
    baseUrl: "https://upstream.example",
    resolveHeaders: ({ capability, agentSession }) => ({
      authorization: `Agent ${agentSession.agent.id}`,
      "x-capability": capability,
    }),
    async fetch(url, init) {
      requests.push({ url, init });
      return Response.json({ id: "message/1", ok: true });
    },
  });
  const result = await handler({
    ctx: {},
    capability: "messages.get",
    arguments: { id: "message/1", verbose: true, "x-tenant": "oracle" },
    agentSession: { agent: { id: "agent-1" } },
  });
  assert.deepEqual(result, { id: "message/1", ok: true });
  assert.equal(
    requests[0].url,
    "https://upstream.example/messages/message%2F1?verbose=true",
  );
  assert.equal(requests[0].init.method, "GET");
  assert.deepEqual(requests[0].init.headers, {
    "content-type": "application/json",
    authorization: "Agent agent-1",
    "x-capability": "messages.get",
    "x-tenant": "oracle",
  });
  assert.equal("body" in requests[0].init, false);

  const generated = createFromOpenAPI(spec, {
    baseUrl: "https://upstream.example",
    defaultHostCapabilities: ["GET", "HEAD"],
    approvalStrength: { GET: "none", POST: "webauthn" },
    location: "https://resource.example/agent/execute",
  });
  assert.equal(generated.providerName, "Message API");
  assert.equal(generated.providerDescription, "Read and create messages");
  assert.deepEqual(generated.defaultHostCapabilities, ["messages.get"]);
  assert.deepEqual(
    generated.capabilities.map(({ name, approvalStrength, location }) => ({
      name,
      approvalStrength,
      location,
    })),
    [
      {
        name: "messages.get",
        approvalStrength: "none",
        location: "https://resource.example/agent/execute",
      },
      {
        name: "messages.create",
        approvalStrength: "webauthn",
        location: "https://resource.example/agent/execute",
      },
    ],
  );
  assert.equal(typeof generated.onExecute, "function");
}

async function helperAndSdkContract() {
  assert.deepEqual(
    Object.fromEntries(
      Object.entries(AGENT_AUTH_ERROR_CODES).map(([name, value]) => [name, value.code]),
    ),
    ERROR_CODES,
  );
  assert.equal(
    digest(AGENT_AUTH_ERROR_CODES),
    "f23a45de32a173b70b4d1731a0337f173ec60ca5ce32ce98c48e541e9baf7fb8",
  );
  assert.equal(CLIENT_ERROR_CODES, AGENT_AUTH_ERROR_CODES);
  assert.deepEqual(agentAuthChallenge("https://provider.example/api/auth/"), {
    "WWW-Authenticate":
      'AgentAuth discovery="https://provider.example/.well-known/agent-configuration"',
  });
  const error = agentError(
    "FORBIDDEN",
    AGENT_AUTH_ERROR_CODES.CAPABILITY_BLOCKED,
    "Blocked by policy",
    { "X-Agent-Auth": "oracle" },
    { capabilities: ["mail.send"] },
  );
  assert.equal(error.statusCode, 403);
  assert.deepEqual(error.body, {
    error: "capability_blocked",
    message: "Blocked by policy",
    capabilities: ["mail.send"],
  });
  assert.deepEqual(error.headers, { "X-Agent-Auth": "oracle" });
  assert.deepEqual(asyncResult("https://provider.example/jobs/1", 7), {
    __type: "async",
    statusUrl: "https://provider.example/jobs/1",
    retryAfter: 7,
  });
  const body = new ReadableStream();
  assert.deepEqual(streamResult(body, { "X-Stream": "yes" }), {
    __type: "stream",
    body,
    headers: { "X-Stream": "yes" },
  });

  await verifyAgentRequestContract();
  await sdkDiscoveryAndSigningContract();
}

function digest(value) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

async function verifyAgentRequestContract() {
  let received;
  const auth = {
    options: { baseURL: "https://provider.example/api/auth/" },
    async handler(request) {
      received = request;
      return Response.json({ agent: { id: "agent-1" }, capabilities: ["mail.read"] });
    },
  };
  assert.equal(
    await verifyAgentRequest(new Request("https://resource.example/execute"), auth),
    null,
  );
  const session = await verifyAgentRequest(
    new Request("https://resource.example/execute", {
      headers: { authorization: "Bearer signed-agent-jwt", "x-request-id": "req-1" },
    }),
    auth,
  );
  assert.deepEqual(session, {
    agent: { id: "agent-1" },
    capabilities: ["mail.read"],
  });
  assert.equal(received.url, "https://provider.example/api/auth/agent/session");
  assert.equal(received.method, "GET");
  assert.equal(received.headers.get("authorization"), "Bearer signed-agent-jwt");
  assert.equal(received.headers.get("x-request-id"), "req-1");
  assert.equal(
    await verifyAgentRequest(
      new Request("https://resource.example/execute", {
        headers: { authorization: "Bearer rejected" },
      }),
      { ...auth, handler: async () => new Response(null, { status: 401 }) },
    ),
    null,
  );
}

async function sdkDiscoveryAndSigningContract() {
  const requested = [];
  const discovered = await discoverProvider("https://provider.example/", async (url, init) => {
    requested.push({ url, method: init.method, accept: init.headers.accept });
    if (requested.length < 2) return new Response(null, { status: 404 });
    return Response.json(discoveryDocument());
  });
  assert.deepEqual(discovered, discoveryDocument());
  assert.deepEqual(requested, [
    {
      url: "https://provider.example/.well-known/agent-configuration",
      method: "GET",
      accept: "application/json",
    },
    {
      url: "https://provider.example/api/auth/agent-configuration",
      method: "GET",
      accept: "application/json",
    },
  ]);

  const storage = new MemoryStorage();
  const client = new AgentAuthClient({
    providers: [discoveryDocument()],
    storage,
  });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.deepEqual(await client.listProviders(), [
    {
      name: "agent-auth",
      description: "Agent Auth enabled service",
      issuer: "https://provider.example/api/auth",
    },
  ]);

  const keypair = await generateKeypair();
  assert.equal(keypair.publicKey.kty, "OKP");
  assert.equal(keypair.publicKey.crv, "Ed25519");
  assert.equal(keypair.publicKey.kid, keypair.privateKey.kid);
  assert.equal("d" in keypair.publicKey, false);
  assert.equal(typeof keypair.privateKey.d, "string");

  const hostToken = await signHostJWT({
    hostKeypair: keypair,
    audience: "https://provider.example/api/auth",
    agentPublicKey: keypair.publicKey,
    hostName: "Oracle host",
  });
  assert.deepEqual(decodeProtectedHeader(hostToken), {
    alg: "EdDSA",
    typ: "host+jwt",
    kid: keypair.publicKey.kid,
  });
  const hostClaims = decodeJwt(hostToken);
  assert.equal(hostClaims.iss, keypair.publicKey.kid);
  assert.equal(hostClaims.sub, keypair.publicKey.kid);
  assert.equal(hostClaims.aud, "https://provider.example/api/auth");
  assert.equal(hostClaims.host_name, "Oracle host");
  assert.deepEqual(hostClaims.host_public_key, keypair.publicKey);
  assert.deepEqual(hostClaims.agent_public_key, keypair.publicKey);
  assert.equal(hostClaims.exp - hostClaims.iat, 60);
  assert.equal(typeof hostClaims.jti, "string");

  const agentToken = await signAgentJWT({
    agentKeypair: keypair,
    agentId: "agent-1",
    audience: "https://provider.example/api/auth",
    capabilities: ["mail.read"],
    htm: "POST",
    htu: "https://provider.example/api/auth/capability/execute",
    ath: "access-token-hash",
  });
  assert.deepEqual(decodeProtectedHeader(agentToken), {
    alg: "EdDSA",
    typ: "agent+jwt",
    kid: keypair.publicKey.kid,
  });
  const agentClaims = decodeJwt(agentToken);
  assert.equal(agentClaims.sub, "agent-1");
  assert.equal(agentClaims.aud, "https://provider.example/api/auth");
  assert.deepEqual(agentClaims.capabilities, ["mail.read"]);
  assert.equal(agentClaims.htm, "POST");
  assert.equal(agentClaims.htu, "https://provider.example/api/auth/capability/execute");
  assert.equal(agentClaims.ath, "access-token-hash");
  assert.equal(agentClaims.exp - agentClaims.iat, 60);
  assert.equal(typeof agentClaims.jti, "string");
}
