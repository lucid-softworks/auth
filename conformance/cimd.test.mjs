import { readFile } from "node:fs/promises";
import { describe, expect, test } from "vitest";
import {
  cimd,
  createCimdClientDiscovery,
  isCimdClientIdUrlCandidate,
  validateCimdMetadata,
  validateClientIdUrl,
} from "@better-auth/cimd";

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
});
