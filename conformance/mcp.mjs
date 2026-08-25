import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import {
  createMcpProtectedRequestHandler,
  mcp,
  requireMcpAuth,
} from "@better-auth/mcp";
import {
  Client,
  ClientCredentialsProvider,
  StreamableHTTPClientTransport,
  discoverOAuthProtectedResourceMetadata,
  discoverOAuthServerInfo,
} from "@modelcontextprotocol/client";
import { createInsufficientScopeError } from "better-auth/oauth2";

const CACHE_CONTROL =
  "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400";

export async function mcpConformance() {
  await exportsAndPresetContract();
  resourceValidationContract();
  await protectedResourceMetadataContract();
  await protectedRequestHandlerContract();
  await requireMcpAuthContract();
  console.log("ok - MCP official server and resource-wrapper contract");
}

export async function mcpNativeConformance(origin) {
  const resource = `${origin}/mcp`;
  const issuer = `${origin}/api/auth`;
  const resourceMetadata = await discoverOAuthProtectedResourceMetadata(
    new URL(resource),
  );
  assert.equal(resourceMetadata.resource, resource);
  assert.deepEqual(resourceMetadata.authorization_servers, [issuer]);
  assert.deepEqual(resourceMetadata.scopes_supported, ["mcp.read"]);

  const serverInfo = await discoverOAuthServerInfo(new URL(resource));
  assert.equal(serverInfo.authorizationServerUrl, issuer);
  assert.equal(serverInfo.authorizationServerMetadata?.issuer, issuer);
  assert.equal(
    serverInfo.authorizationServerMetadata?.token_endpoint,
    `${issuer}/oauth2/token`,
  );

  const provider = new ClientCredentialsProvider({
    clientId: "mcp-conformance-client",
    clientSecret: "mcp-conformance-secret",
    scope: "mcp.read",
    expectedIssuer: issuer,
  });
  const transport = new StreamableHTTPClientTransport(new URL(resource), {
    authProvider: provider,
    onInsufficientScope: "throw",
  });
  const client = new Client({
    name: "lucid-auth-official-mcp-client",
    version: "1.0.0",
  });
  try {
    await client.connect(transport);
    assert.deepEqual(client.getServerVersion(), {
      name: "lucid-auth-conformance",
      version: "1.0.0",
    });
    assert.equal(provider.tokens()?.token_type, "Bearer");
    assert.equal(provider.tokens()?.scope, "mcp.read");
  } finally {
    await client.close();
  }
  console.log("ok - official MCP v2 client against native server");
}

async function exportsAndPresetContract() {
  const packageJson = JSON.parse(
    await readFile(
      new URL("node_modules/@better-auth/mcp/package.json", import.meta.url),
    ),
  );
  assert.equal(packageJson.version, "1.7.1");
  assert.deepEqual(Object.keys(packageJson.exports), ["."]);
  assert.deepEqual(
    Object.keys(await import("@better-auth/mcp")).sort(),
    ["createMcpProtectedRequestHandler", "mcp", "requireMcpAuth"],
  );

  const existingResource = {
    identifier: "https://resource.example/mcp",
    name: "MCP resource",
    dpopBoundAccessTokensRequired: true,
  };
  const plugin = mcp({
    loginPage: "/login",
    consentPage: "/consent",
    resource: existingResource.identifier,
    resources: [existingResource, "https://resource.example/other"],
    clientRegistrationDefaultResources: ["https://resource.example/other"],
  });
  assert.equal(plugin.id, "oauth-provider");
  assert.equal(plugin.version, "1.7.1");
  assert.equal(plugin.options.refreshTokenReuseInterval, 30);
  assert.deepEqual(plugin.options.resources, [
    existingResource,
    "https://resource.example/other",
  ]);
  assert.deepEqual(plugin.options.clientRegistrationDefaultResources, [
    "https://resource.example/other",
    existingResource.identifier,
  ]);
  assert.deepEqual(Object.keys(plugin.schema), [
    "oauthClient",
    "oauthResource",
    "oauthClientResource",
    "oauthRefreshToken",
    "oauthAccessToken",
    "oauthConsent",
    "oauthClientAssertion",
  ]);
  assert.equal(plugin.rateLimit.length, 6);

  const strict = mcp({
    loginPage: "/login",
    consentPage: "/consent",
    resource: "https://resource.example/mcp",
    refreshTokenReuseInterval: 0,
  });
  assert.equal(strict.options.refreshTokenReuseInterval, 0);
}

function resourceValidationContract() {
  for (const resource of [
    "https://resource.example/mcp",
    "http://localhost:3000/mcp",
    "http://127.255.0.1/mcp",
    "http://[::1]/mcp",
  ]) {
    assert.doesNotThrow(() => preset(resource));
  }

  for (const [resource, message] of [
    [undefined, "single URL string"],
    [42, "single URL string"],
    ["/mcp", "absolute URL"],
    ["https://user:secret@resource.example/mcp", "must not contain credentials"],
    ["https://resource.example/mcp?tenant=one", "must not contain a query"],
    ["https://resource.example/mcp#fragment", "must not contain a fragment"],
    ["http://resource.example/mcp", "must use HTTPS"],
    ["http://localhost.example/mcp", "must use HTTPS"],
    ["http://128.0.0.1/mcp", "must use HTTPS"],
  ]) {
    assert.throws(() => preset(resource), new RegExp(message));
  }
}

async function protectedResourceMetadataContract() {
  const resource = "https://resource.example/mcp/";
  const plugin = mcp({
    loginPage: "/login",
    consentPage: "/consent",
    resource,
    disableJwtPlugin: true,
    scopes: [
      "openid",
      "profile",
      "email",
      "phone",
      "address",
      "offline_access",
      "mcp.read",
      "mcp.write",
      "mcp.admin",
    ],
    advertisedMetadata: {
      scopes_supported: ["openid", "mcp.read", "mcp.admin"],
    },
    resources: [
      {
        identifier: resource,
        name: "Protected MCP",
        dpopBoundAccessTokensRequired: true,
      },
    ],
    dpop: { signingAlgorithms: ["ES256", "EdDSA"] },
  });
  const context = {
    baseURL: "https://issuer.example/api/auth",
    options: { advanced: {} },
  };
  const expected = {
    resource,
    authorization_servers: ["https://issuer.example/api/auth"],
    bearer_methods_supported: ["header"],
    dpop_signing_alg_values_supported: ["ES256", "EdDSA"],
    dpop_bound_access_tokens_required: true,
    scopes_supported: ["mcp.read", "mcp.admin"],
  };

  for (const path of [
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
  ]) {
    const get = await invokeOnRequest(plugin, context, path, "GET");
    assert.equal(get.status, 200);
    assert.equal(get.headers.get("content-type"), "application/json");
    assert.equal(get.headers.get("cache-control"), CACHE_CONTROL);
    assert.deepEqual(await get.json(), expected);

    const head = await invokeOnRequest(plugin, context, path, "HEAD");
    assert.equal(head.status, 200);
    assert.equal(head.headers.get("content-type"), "application/json");
    assert.equal(head.headers.get("cache-control"), CACHE_CONTROL);
    assert.equal(await head.text(), "");

    const post = await invokeOnRequest(plugin, context, path, "POST");
    assert.equal(post.status, 405);
    assert.equal(post.headers.get("allow"), "GET, HEAD");
    assert.equal(await post.text(), "");
  }

  const skipped = {
    ...context,
    options: { advanced: { skipTrailingSlashes: true } },
  };
  assert.equal(
    (await invokeOnRequest(
      plugin,
      skipped,
      "/.well-known/oauth-protected-resource/mcp///",
      "GET",
    )).status,
    200,
  );
  assert.equal(
    await plugin.onRequest(
      new Request("https://issuer.example/not-mcp"),
      context,
    ),
    undefined,
  );
}

async function protectedRequestHandlerContract() {
  const introspection = await introspectionServer();
  const audience = `${introspection.origin}/mcp`;
  try {
    const handler = createMcpProtectedRequestHandler(
      {
        issuer: introspection.origin,
        audience,
        requiredScopes: ["mcp.read"],
        challengeScopes: ["mcp.read", "mcp.write", "mcp.read"],
        remoteVerify: {
          introspectUrl: `${introspection.origin}/introspect`,
          clientId: "resource-server",
          clientSecret: "secret",
          force: true,
        },
      },
      (_request, claims) => Response.json({ subject: claims.sub }),
    );

    const missing = await handler(new Request(audience, { method: "POST" }));
    await assertJsonRpcChallenge(missing, 401, "missing authorization header");
    assert.equal(
      missing.headers.get("www-authenticate"),
      `Bearer resource_metadata="${introspection.origin}/.well-known/oauth-protected-resource/mcp", scope="mcp.read mcp.write"`,
    );
    assert.equal(missing.headers.get("cache-control"), null);

    const accepted = await handler(
      protectedRequest(audience, "active:mcp.read mcp.write"),
    );
    assert.equal(accepted.status, 200);
    assert.deepEqual(await accepted.json(), { subject: "oracle-user" });

    const insufficient = await handler(
      protectedRequest(audience, "active:mcp.other"),
    );
    await assertJsonRpcChallenge(
      insufficient,
      403,
      "access token is missing required scope: mcp.read",
    );
    assert.match(
      insufficient.headers.get("www-authenticate"),
      /^Bearer error="insufficient_scope", scope="mcp.read", /,
    );

    const inactive = await handler(protectedRequest(audience, "inactive"));
    await assertJsonRpcChallenge(inactive, 401, "token inactive");

    const operationScope = createMcpProtectedRequestHandler(
      {
        issuer: introspection.origin,
        audience,
        remoteVerify: {
          introspectUrl: `${introspection.origin}/introspect`,
          clientId: "resource-server",
          clientSecret: "secret",
          force: true,
        },
      },
      () => {
        throw createInsufficientScopeError(["tools.call"]);
      },
    );
    const challenged = await operationScope(
      protectedRequest(audience, "active:mcp.read"),
    );
    await assertJsonRpcChallenge(
      challenged,
      403,
      "access token is missing required scope: tools.call",
    );
    assert.match(challenged.headers.get("www-authenticate"), /scope="tools.call"/);

    assert.throws(
      () =>
        createMcpProtectedRequestHandler(
          { issuer: introspection.origin, audience: "https://resource.example/mcp?x=1" },
          () => Response.json({ ok: true }),
        ),
      /must not contain a query/,
    );
    const invalidScopes = createMcpProtectedRequestHandler(
      {
        issuer: introspection.origin,
        audience,
        requiredScopes: ["bad scope"],
      },
      () => Response.json({ ok: true }),
    );
    await assert.rejects(
      () => invalidScopes(new Request(audience)),
      /invalid challenge scope/,
    );
  } finally {
    await introspection.close();
  }
}

async function requireMcpAuthContract() {
  assert.throws(
    () =>
      requireMcpAuth(
        { $context: Promise.resolve({ baseURL: "", internalAdapter: {} }) },
        () => Response.json({ ok: true }),
        { resource: "https://resource.example/mcp?x=1" },
      ),
    /must not contain a query/,
  );
  const wrapped = requireMcpAuth(
    { $context: Promise.resolve({ baseURL: "", internalAdapter: {} }) },
    () => Response.json({ ok: true }),
  );
  await assert.rejects(
    () => wrapped(new Request("https://resource.example/mcp")),
    /requires a resolvable base URL/,
  );
}

function preset(resource) {
  return mcp({
    loginPage: "/login",
    consentPage: "/consent",
    resource,
  });
}

async function invokeOnRequest(plugin, context, path, method) {
  const handled = await plugin.onRequest(
    new Request(`https://issuer.example${path}`, { method }),
    context,
  );
  assert.ok(handled?.response, `${method} ${path} was not intercepted`);
  return handled.response;
}

function protectedRequest(audience, token) {
  return new Request(audience, {
    method: "POST",
    headers: { authorization: `Bearer ${token}` },
  });
}

async function assertJsonRpcChallenge(response, status, message) {
  assert.equal(response.status, status);
  assert.equal(response.headers.get("content-type"), "application/json");
  assert.deepEqual(await response.clone().json(), {
    jsonrpc: "2.0",
    error: { code: -32000, message },
    id: null,
  });
}

async function introspectionServer() {
  const server = createServer((request, response) => {
    if (request.url !== "/introspect") {
      response.writeHead(404).end();
      return;
    }
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const token = new URLSearchParams(body).get("token") ?? "";
      const scope = token.startsWith("active:") ? token.slice(7) : "";
      response.writeHead(200, { "content-type": "application/json" });
      response.end(
        JSON.stringify({
          active: token.startsWith("active:"),
          iss: `http://127.0.0.1:${server.address().port}`,
          aud: `http://127.0.0.1:${server.address().port}/mcp`,
          sub: "oracle-user",
          scope,
          exp: Math.floor(Date.now() / 1000) + 300,
        }),
      );
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  return {
    origin,
    close: () => new Promise((resolve, reject) => server.close((error) => {
      if (error) reject(error);
      else resolve();
    })),
  };
}
