import { readFile } from "node:fs/promises";
import { describe, expect, test } from "vitest";
import { betterAuth } from "better-auth";
import {
  cimd,
  createCimdClientDiscovery,
  isCimdClientIdUrlCandidate,
  validateCimdMetadata,
  validateClientIdUrl,
} from "@better-auth/cimd";
import { oauthProvider } from "@better-auth/oauth-provider";

const packageJson = async (name) =>
  JSON.parse(
    await readFile(new URL(`node_modules/${name}/package.json`, import.meta.url), "utf8"),
  );

describe("@better-auth/cimd@1.7.1 oracle", () => {
  test("pins the server-only package and public plugin surface", async () => {
    expect((await packageJson("@better-auth/cimd")).version).toBe("1.7.1");
    expect((await packageJson("@better-auth/oauth-provider")).version).toBe("1.7.1");
    expect((await packageJson("better-auth")).version).toBe("1.7.1");

    const transport = async () => new Response("{}", { status: 200 });
    const plugin = cimd({ fetchClientMetadataResource: transport });
    const discovery = createCimdClientDiscovery({ fetchClientMetadataResource: transport });
    expect(plugin).toMatchObject({ id: "cimd", version: "1.7.1" });
    expect(plugin.endpoints).toBeUndefined();
    expect(discovery).toMatchObject({
      id: "cimd",
      discoveryMetadata: { client_id_metadata_document_supported: true },
      fetchClientMetadataResource: transport,
    });
  });

  test("keeps HTTPS candidate routing separate from the SSRF boundary", () => {
    expect([
      "https://127.0.0.1",
      "HTTPS://client.example",
      "http://client.example/doc",
      "not a url",
    ].map((value) => isCimdClientIdUrlCandidate(value))).toEqual([
      true,
      true,
      false,
      false,
    ]);

    expect(validateClientIdUrl("https://client.example/doc")).toBeNull();
    expect(validateClientIdUrl("https://client.example/")).toBeNull();
    expect(validateClientIdUrl("https://client.example/doc?q=1")).toBeNull();
    expect(validateClientIdUrl("https://client.example")).toBe(
      "client_id URL MUST contain an explicit path component",
    );
    expect(validateClientIdUrl("https://127.0.0.1/doc")).toBe(
      "client_id URL must not target a private or reserved address",
    );
    expect(validateClientIdUrl("https://client.example/a/%2e%2e/doc")).toBe(
      "client_id URL MUST NOT contain dot segments",
    );
  });

  test("defaults generic metadata, strips unknown members, and warns on draft SHOULDs", () => {
    expect(
      validateCimdMetadata("https://client.example/?mode=test", {
        client_id: "https://client.example/?mode=test",
        future_extension: true,
      }),
    ).toEqual({
      valid: true,
      metadata: {
        client_id: "https://client.example/?mode=test",
        token_endpoint_auth_method: "none",
      },
      warnings: [
        "client_id URL path / is NOT RECOMMENDED (§3)",
        "client_id URL SHOULD NOT contain a query string (§3)",
      ],
    });
  });

  test("pins profile, ownership, origin, and authentication validation", () => {
    const id = "https://client.example/metadata.json";
    expect(
      validateCimdMetadata(id, { client_id: id }, { metadataProfile: "mcp-2026-07-28" }),
    ).toEqual({ valid: false, error: "client_name must be a non-empty string" });
    expect(validateCimdMetadata(id, { client_id: id, skipConsent: true })).toEqual({
      valid: false,
      error: 'metadata document MUST NOT contain "skipConsent"',
    });
    expect(
      validateCimdMetadata(id, {
        client_id: id,
        token_endpoint_auth_method: "client_secret_basic",
      }),
    ).toEqual({
      valid: false,
      error:
        'symmetric auth method "client_secret_basic" is prohibited for Client ID Metadata Document clients',
    });
    expect(validateCimdMetadata(id, { client_id: id, client_uri: "https://other.example" })).toEqual({
      valid: false,
      error:
        'client_uri value "https://other.example" must have the same origin as client_id (https://client.example)',
    });
  });

  test("accepts public asymmetric JWKs and rejects private or symmetric material", () => {
    const id = "https://client.example/metadata.json";
    expect(
      validateCimdMetadata(id, {
        client_id: id,
        token_endpoint_auth_method: "private_key_jwt",
        jwks: { keys: [{ kty: "RSA", n: "n", e: "AQAB", alg: "PS256" }] },
      }).valid,
    ).toBe(true);
    for (const key of [
      { kty: "oct", k: "secret" },
      { kty: "RSA", n: "n", e: "AQAB", d: "private" },
      { kty: "EC", crv: "secp256k1", x: "x", y: "y" },
      { kty: "EC", crv: "P-256", x: "x", y: "y", alg: "ES384" },
    ]) {
      expect(
        validateCimdMetadata(id, {
          client_id: id,
          token_endpoint_auth_method: "private_key_jwt",
          jwks: { keys: [key] },
        }),
      ).toEqual({
        valid: false,
        error: "jwks must contain only structurally valid public keys",
      });
    }
  });

  test("captures discovery metadata, transport input, cache reuse, and creation callback", async () => {
    const baseURL = "https://issuer.example.test/api/auth";
    const clientId = "https://metadata.example.test/client.json";
    const requests = [];
    const callbacks = [];
    const transport = async (input, init) => {
      requests.push({
        input: String(input),
        accept: init.headers.get("accept"),
        redirect: init.redirect,
        hasSignal: init.signal instanceof AbortSignal,
      });
      return new Response(
        JSON.stringify({
          client_id: clientId,
          client_name: "Oracle client",
          redirect_uris: ["https://client.example.test/callback"],
          unknown: "stripped",
        }),
        {
          status: 200,
          headers: {
            "content-type": "application/metadata+json; charset=utf-8",
            "cache-control": "max-age=60",
          },
        },
      );
    };
    const auth = betterAuth({
      baseURL,
      secret: "c".repeat(32),
      logger: { disabled: true },
      plugins: [
        oauthProvider({
          loginPage: "/login",
          consentPage: "/consent",
          disableJwtPlugin: true,
        }),
        cimd({
          fetchClientMetadataResource: transport,
          onClientCreated: ({ client, clientMetadataDocument }) => {
            callbacks.push({
              clientId: client.clientId,
              name: client.name,
              metadata: clientMetadataDocument,
            });
          },
        }),
      ],
    });

    const metadata = await auth.handler(
      new Request("https://issuer.example.test/.well-known/oauth-authorization-server/api/auth"),
    );
    expect(await metadata.json()).toMatchObject({
      client_id_metadata_document_supported: true,
    });
    const authorizeUrl = new URL(`${baseURL}/oauth2/authorize`);
    authorizeUrl.search = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: "https://client.example.test/callback",
      scope: "openid",
    });
    for (let index = 0; index < 2; index += 1) {
      const response = await auth.handler(new Request(authorizeUrl, { redirect: "manual" }));
      expect(response.status).toBe(302);
    }
    expect(requests).toEqual([
      {
        input: clientId,
        accept: "application/json",
        redirect: "error",
        hasSignal: true,
      },
    ]);
    expect(callbacks).toEqual([
      {
        clientId,
        name: "Oracle client",
        metadata: {
          client_id: clientId,
          client_name: "Oracle client",
          redirect_uris: ["https://client.example.test/callback"],
          token_endpoint_auth_method: "none",
        },
      },
    ]);
  });

  test("captures construction failures and invalid fetch envelopes", async () => {
    const transport = async () =>
      new Response("not json", {
        status: 200,
        headers: { "content-type": "text/plain" },
      });
    expect(() =>
      createCimdClientDiscovery({
        fetchClientMetadataResource: transport,
        maxCacheEntries: 0,
      }),
    ).toThrowError("cimd maxCacheEntries must be a positive integer");
    expect(() =>
      createCimdClientDiscovery({
        fetchClientMetadataResource: transport,
        metadataFetchPolicy: { maximumConcurrentFetches: 0 },
      }),
    ).toThrowError(
      "cimd metadataFetchPolicy.maximumConcurrentFetches must be a positive integer",
    );

    const clientId = "https://metadata.example.test/invalid.json";
    const auth = betterAuth({
      baseURL: "https://issuer.example.test/api/auth",
      secret: "d".repeat(32),
      logger: { disabled: true },
      plugins: [
        oauthProvider({ loginPage: "/login", consentPage: "/consent", disableJwtPlugin: true }),
        cimd({ fetchClientMetadataResource: transport }),
      ],
    });
    const url = new URL("https://issuer.example.test/api/auth/oauth2/authorize");
    url.search = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: "https://client.example.test/callback",
    });
    const response = await auth.handler(new Request(url, { redirect: "manual" }));
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: "invalid_client",
      error_description: 'Metadata document must be JSON (got Content-Type "text/plain")',
    });
  });
});
