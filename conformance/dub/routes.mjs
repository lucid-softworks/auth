import { describe, expect, test, vi } from "vitest";
import {
  authOrigin,
  authServer,
  postJson,
  responseBody,
  signUp,
} from "./helpers.mjs";

async function link(auth, body, headers = {}) {
  return postJson(auth, "/dub/link", body, headers);
}

async function expectResponse(response, status, body) {
  expect(response.status).toBe(status);
  expect(await responseBody(response)).toEqual(body);
}

describe("@dub/better-auth@0.0.6 link route oracle", () => {
  test("publishes exactly one POST descriptor with stripping Zod 3 validation", () => {
    const { plugin } = authServer();
    expect(plugin.id).toBe("dub");
    expect(Object.keys(plugin.endpoints)).toEqual(["linkDub"]);
    const endpoint = plugin.endpoints.linkDub;
    expect(endpoint.path).toBe("/dub/link");
    expect(Object.keys(endpoint)).toEqual(["options", "path"]);
    expect(endpoint.options.method).toBe("POST");
    expect(endpoint.options.body.parse({
      callbackURL: "https://auth.example.test/dashboard",
      unknown: "stripped",
    })).toEqual({ callbackURL: "https://auth.example.test/dashboard" });
    expect(endpoint.options.use).toHaveLength(1);
    expect(endpoint.options.use[0].options).toEqual({});
    expect(endpoint.options).not.toHaveProperty("useSession");
  });

  test("pins missing, empty, null, boolean, number, and relative Zod errors", async () => {
    const { auth } = authServer();
    const cases = [
      [{}, "[body.callbackURL] Required"],
      [{ callbackURL: "" }, "[body.callbackURL] Invalid url"],
      [{ callbackURL: null }, "[body.callbackURL] Expected string, received null"],
      [{ callbackURL: false }, "[body.callbackURL] Expected string, received boolean"],
      [{ callbackURL: 0 }, "[body.callbackURL] Expected string, received number"],
      [{ callbackURL: "/dashboard" }, "[body.callbackURL] Invalid url"],
      [{ callbackUrl: "https://auth.example.test/dashboard" }, "[body.callbackURL] Required"],
    ];
    for (const [body, message] of cases) {
      await expectResponse(await link(auth, body), 400, {
        code: "VALIDATION_ERROR",
        message,
      });
    }
  });

  test("runs truthy non-string and untrusted callback checks before Zod", async () => {
    const { auth } = authServer();
    await expectResponse(await link(auth, { callbackURL: {} }), 400, {
      message: "Invalid callbackURL: expected a string",
    });
    await expectResponse(await link(auth, { callbackURL: [authOrigin] }), 400, {
      message: "Invalid callbackURL: expected a string",
    });
    await expectResponse(await link(auth, { callbackURL: "https://evil.example.test" }), 403, {
      code: "INVALID_CALLBACK_URL",
      message: "Invalid callbackURL",
    });
  });

  test("applies cookie-dependent origin checks but no form-CSRF middleware", async () => {
    const { auth } = authServer();
    const body = { callbackURL: `${authOrigin}/dashboard` };
    for (const headers of [
      { cookie: "other=value" },
      { cookie: "other=value", origin: "null" },
    ]) {
      await expectResponse(await link(auth, body, headers), 403, {
        code: "MISSING_OR_NULL_ORIGIN",
        message: "Missing or null Origin",
      });
    }
    await expectResponse(await link(auth, body, {
      cookie: "other=value",
      origin: "https://evil.example.test",
    }), 403, {
      code: "INVALID_ORIGIN",
      message: "Invalid origin",
    });
    await expectResponse(await link(auth, body, {
      cookie: "other=value",
      origin: authOrigin,
    }), 404, { message: "Dub OAuth is not configured" });
    await expectResponse(await link(auth, body, {
      origin: "https://evil.example.test",
      "sec-fetch-mode": "cors",
      "sec-fetch-site": "cross-site",
    }), 404, { message: "Dub OAuth is not configured" });
  });

  test("returns the exact unconfigured OAuth error and registers no callback/provider", async () => {
    const server = authServer();
    await expectResponse(
      await link(server.auth, { callbackURL: `${authOrigin}/dashboard` }),
      404,
      { message: "Dub OAuth is not configured" },
    );
    expect(Object.values(server.plugin.endpoints).map(endpoint => endpoint.path)).toEqual(["/dub/link"]);
    expect(server.plugin).not.toHaveProperty("providers");
    const callback = await postJson(server.auth, "/oauth2/callback/dub", {});
    expect(callback.status).toBe(404);
  });

  test("pins configured OAuth's empty 500 for anonymous and authenticated callers", async () => {
    const server = authServer({
      pluginOptions: { oauth: { clientId: "client", clientSecret: "secret", pkce: false } },
    });
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const body = { callbackURL: `${authOrigin}/dashboard` };
    const anonymous = await link(server.auth, body);
    expect(anonymous.status).toBe(500);
    expect(await anonymous.text()).toBe("");
    expect(anonymous.headers.getSetCookie()).toEqual([]);

    const signup = await signUp(server.auth, "authenticated-oauth");
    const sessionCookie = signup.headers.getSetCookie()
      .find(value => value.includes(".session_token="))
      .split(";", 1)[0];
    const authenticated = await link(server.auth, body, {
      cookie: sessionCookie,
      origin: authOrigin,
    });
    expect(authenticated.status).toBe(500);
    expect(await authenticated.text()).toBe("");
    expect(authenticated.headers.getSetCookie()).toEqual([]);
    expect(errorSpy).toHaveBeenCalled();
    errorSpy.mockRestore();
  });
});
