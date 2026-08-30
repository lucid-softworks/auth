import { readFile } from "node:fs/promises";
import { describe, expect, test } from "vitest";
import * as ssoModule from "@better-auth/sso";
import * as ssoClientModule from "@better-auth/sso/client";
import { betterAuth } from "better-auth";
import { packageJson, packageLock } from "./infra-email.helpers.mjs";

const runtimeExports = [
  "DEFAULT_CLOCK_SKEW_MS",
  "DEFAULT_MAX_SAML_METADATA_SIZE",
  "DEFAULT_MAX_SAML_RESPONSE_SIZE",
  "DataEncryptionAlgorithm",
  "DigestAlgorithm",
  "DiscoveryError",
  "KeyEncryptionAlgorithm",
  "REQUIRED_DISCOVERY_FIELDS",
  "SignatureAlgorithm",
  "computeDiscoveryUrl",
  "deriveSAMLIdentityProviderEntityID",
  "deriveSAMLServiceProviderPolicy",
  "discoverOIDCConfig",
  "fetchDiscoveryDocument",
  "needsRuntimeDiscovery",
  "normalizeDiscoveryUrls",
  "normalizeUrl",
  "selectTokenEndpointAuthMethod",
  "sso",
  "validateDiscoveryDocument",
  "validateDiscoveryUrl",
  "validateSAMLTimestamp",
];

const endpointInventory = [
  ["spMetadata", "/sso/saml2/sp/metadata", "GET"],
  ["registerSSOProvider", "/sso/register", "POST"],
  ["signInSSO", "/sign-in/sso", "POST"],
  ["callbackSSO", "/sso/callback/:providerId", "GET"],
  ["callbackSSOShared", "/sso/callback", "GET"],
  ["acsEndpoint", "/sso/saml2/sp/acs/:providerId", ["GET", "POST"]],
  ["sloEndpoint", "/sso/saml2/sp/slo/:providerId", ["GET", "POST"]],
  ["initiateSLO", "/sso/saml2/logout/:providerId", "POST"],
  ["listSSOProviders", "/sso/providers", "GET"],
  ["getSSOProvider", "/sso/get-provider", "GET"],
  ["updateSSOProvider", "/sso/update-provider", "POST"],
  ["deleteSSOProvider", "/sso/delete-provider", "POST"],
];

describe("@better-auth/sso@1.7.1 artifact oracle", () => {
  test("pins the immutable package and its two published subpaths", async () => {
    const pkg = await packageJson("@better-auth/sso");
    const locked = (await packageLock()).packages["node_modules/@better-auth/sso"];
    expect(pkg.version).toBe("1.7.1");
    expect(pkg.exports).toEqual({
      ".": {
        "dev-source": "./src/index.ts",
        types: "./dist/index.d.mts",
        default: "./dist/index.mjs",
      },
      "./client": {
        "dev-source": "./src/client.ts",
        types: "./dist/client.d.mts",
        default: "./dist/client.mjs",
      },
    });
    expect(locked.resolved).toBe(
      "https://registry.npmjs.org/@better-auth/sso/-/sso-1.7.1.tgz",
    );
    expect(locked.integrity).toBe(
      "sha512-fkGNMO8W5uNJSHAlvSe4Gxm1NVTQT4JFS7JpCNIxUAl5UyskE1yFXc2NH0KjcvSbR1RfgrqUgUevOjOjcSUKcg==",
    );
    expect("52d502f6460fd98a199184b7a8ba7343e4bf1606").toHaveLength(40);
    expect(Object.keys(ssoModule).sort()).toEqual(runtimeExports.sort());
    expect(Object.keys(ssoClientModule)).toEqual(["ssoClient"]);
  });

  test("publishes the exact server and client descriptors", () => {
    const plugin = ssoModule.sso();
    expect({ id: plugin.id, version: plugin.version }).toEqual({
      id: "sso",
      version: "1.7.1",
    });
    expect(Object.entries(plugin.endpoints).map(([name, endpoint]) => [
      name,
      endpoint.path,
      endpoint.options.method,
    ])).toEqual(endpointInventory);
    expect(Object.keys(plugin.schema)).toEqual(["ssoProvider"]);
    expect(Object.keys(plugin.schema.ssoProvider.fields)).toEqual([
      "issuer",
      "oidcConfig",
      "samlConfig",
      "userId",
      "providerId",
      "organizationId",
      "domain",
    ]);
    expect(ssoClientModule.ssoClient()).toMatchObject({
      id: "sso-client",
      version: "1.7.1",
      pathMethods: {
        "/sso/providers": "GET",
        "/sso/get-provider": "GET",
      },
    });
  });

  test("adds only the two domain-verification endpoints and field", () => {
    const plugin = ssoModule.sso({ domainVerification: { enabled: true } });
    expect(Object.entries(plugin.endpoints).slice(-2).map(([name, endpoint]) => [
      name,
      endpoint.path,
      endpoint.options.method,
    ])).toEqual([
      ["requestDomainVerification", "/sso/request-domain-verification", "POST"],
      ["verifyDomain", "/sso/verify-domain", "POST"],
    ]);
    expect(Object.keys(plugin.schema.ssoProvider.fields).at(-1)).toBe("domainVerified");
  });

  test("pins every declaration exported from the package root", async () => {
    const declarations = await readFile(
      new URL("node_modules/@better-auth/sso/dist/index.d.mts", import.meta.url),
      "utf8",
    );
    const exportBlock = declarations.match(/export \{[^}]+\};/g)?.at(-1);
    const exports = exportBlock
      ?.slice("export {".length, -2)
      .split(",")
      .map((entry) => entry.trim())
      .sort();
    expect(exports).toEqual([
      "AlgorithmValidationOptions",
      "DEFAULT_CLOCK_SKEW_MS",
      "DEFAULT_MAX_SAML_METADATA_SIZE",
      "DEFAULT_MAX_SAML_RESPONSE_SIZE",
      "DataEncryptionAlgorithm",
      "DeprecatedAlgorithmBehavior",
      "DigestAlgorithm",
      "DiscoverOIDCConfigParams",
      "DiscoveryError",
      "DiscoveryErrorCode",
      "HydratedOIDCConfig",
      "KeyEncryptionAlgorithm",
      "OIDCConfig",
      "OIDCDiscoveryDocument",
      "REQUIRED_DISCOVERY_FIELDS",
      "RequiredDiscoveryField",
      "SAMLConditions",
      "SAMLConfig",
      "SAMLIdentityProviderMetadata",
      "SAMLServiceProviderPolicy",
      "SSOOIDCUserResolutionInput",
      "SSOOptions",
      "SSOPlugin",
      "SSOProvider",
      "SSOProviderMutationGuardContext",
      "SSOProviderMutationGuardInput",
      "SSOProviderReference",
      "SSOProviderUserProfile",
      "SSOSAMLUserResolutionInput",
      "SSOUserResolution",
      "SSOUserResolutionContext",
      "SSOUserResolutionInput",
      "SignatureAlgorithm",
      "TimestampValidationOptions",
      "computeDiscoveryUrl",
      "deriveSAMLIdentityProviderEntityID",
      "deriveSAMLServiceProviderPolicy",
      "discoverOIDCConfig",
      "fetchDiscoveryDocument",
      "needsRuntimeDiscovery",
      "normalizeDiscoveryUrls",
      "normalizeUrl",
      "selectTokenEndpointAuthMethod",
      "sso",
      "validateDiscoveryDocument",
      "validateDiscoveryUrl",
      "validateSAMLTimestamp",
    ].sort());
  });

  test("pins generated SAML service-provider metadata", async () => {
    const baseURL = "https://example.com/api/auth";
    const auth = betterAuth({
      baseURL,
      secret: "S".repeat(32),
      logger: { disabled: true },
      plugins: [
        ssoModule.sso({
          saml: { enableSingleLogout: true },
          defaultSSO: [{
            providerId: "saml-provider",
            domain: "example.com",
            samlConfig: {
              issuer: "https://sp.example.com/entity?a=1&b=2",
              entryPoint: "https://idp.example.com/sso",
              idpMetadata: { entityID: "https://idp.example.com" },
              wantAssertionsSigned: true,
              authnRequestsSigned: true,
              identifierFormat:
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            },
          }],
        }),
      ],
    });
    const response = await auth.handler(
      new Request(
        baseURL + "/sso/saml2/sp/metadata?providerId=saml-provider",
      ),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/xml");
    expect(await response.text()).toBe(
      '<EntityDescriptor entityID="https://sp.example.com/entity?a=1&amp;b=2" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:assertion="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat><SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com/api/auth/sso/saml2/sp/slo/saml-provider"></SingleLogoutService><SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://example.com/api/auth/sso/saml2/sp/slo/saml-provider"></SingleLogoutService><AssertionConsumerService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com/api/auth/sso/saml2/sp/acs/saml-provider"></AssertionConsumerService></SPSSODescriptor></EntityDescriptor>',
    );
  });
});
