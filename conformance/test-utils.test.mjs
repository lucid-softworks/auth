import { describe, expect, test } from "vitest";
import { testUtils } from "better-auth/plugins";
import {
  convertSetCookieToCookie,
  createHttpTestServer,
  getHttpTestInstance,
  getTestInstance,
} from "better-auth/test";

function testContext({ organization = false } = {}) {
  return {
    adapter: {},
    generateId: () => "generated-id",
    hasPlugin: (id) => organization && id === "organization",
    internalAdapter: {},
  };
}

function helperNames(plugin, contextOptions) {
  return Object.keys(plugin.init(testContext(contextOptions)).context.test).sort();
}

describe("better-auth@1.7.1 Test Utils oracle", () => {
  test("snapshots the server plugin descriptor and sole option", () => {
    const defaults = testUtils();
    const capture = testUtils({ captureOTP: true });

    expect({
      dependencies: defaults.dependencies ?? [],
      descriptorKeys: Object.keys(defaults).sort(),
      id: defaults.id,
      options: defaults.options,
      version: defaults.version,
    }).toMatchInlineSnapshot(`
      {
        "dependencies": [],
        "descriptorKeys": [
          "id",
          "init",
          "options",
          "version",
        ],
        "id": "test-utils",
        "options": {},
        "version": "1.7.1",
      }
    `);
    expect(capture.options).toEqual({ captureOTP: true });
    expect(Object.keys(capture.options)).toEqual(["captureOTP"]);
  });

  test("exposes helpers only when their prerequisite is present", () => {
    expect({
      base: helperNames(testUtils()),
      captureOTP: helperNames(testUtils({ captureOTP: true })),
      organization: helperNames(testUtils(), { organization: true }),
      organizationAndCaptureOTP: helperNames(
        testUtils({ captureOTP: true }),
        { organization: true },
      ),
    }).toMatchInlineSnapshot(`
      {
        "base": [
          "createUser",
          "deleteUser",
          "getAuthHeaders",
          "getCookies",
          "login",
          "saveUser",
        ],
        "captureOTP": [
          "clearOTPs",
          "createUser",
          "deleteUser",
          "getAuthHeaders",
          "getCookies",
          "getOTP",
          "login",
          "saveUser",
        ],
        "organization": [
          "addMember",
          "createOrganization",
          "createUser",
          "deleteOrganization",
          "deleteUser",
          "getAuthHeaders",
          "getCookies",
          "login",
          "saveOrganization",
          "saveUser",
        ],
        "organizationAndCaptureOTP": [
          "addMember",
          "clearOTPs",
          "createOrganization",
          "createUser",
          "deleteOrganization",
          "deleteUser",
          "getAuthHeaders",
          "getCookies",
          "getOTP",
          "login",
          "saveOrganization",
          "saveUser",
        ],
      }
    `);
  });

  test("does not define an HTTP or persistence surface", () => {
    const plugin = testUtils();

    for (const property of [
      "routes",
      "endpoints",
      "schema",
      "cookies",
      "rateLimit",
      "rateLimits",
    ]) {
      expect(plugin).not.toHaveProperty(property);
    }
  });

  test("exports the Better Auth Vitest and Node harness functions", () => {
    expect({
      convertSetCookieToCookie: typeof convertSetCookieToCookie,
      createHttpTestServer: typeof createHttpTestServer,
      getHttpTestInstance: typeof getHttpTestInstance,
      getTestInstance: typeof getTestInstance,
    }).toEqual({
      convertSetCookieToCookie: "function",
      createHttpTestServer: "function",
      getHttpTestInstance: "function",
      getTestInstance: "function",
    });
  });
});
