import { describe, expect, test, vi } from "vitest";
import { USER_EVENT_TYPES, dash } from "@better-auth/infra";
import { dashClient } from "@better-auth/infra/client";
import { infraText, packageJson, packageLock } from "./infra-email.helpers.mjs";

describe("@better-auth/infra@0.4.3 Dash substrate oracle", () => {
  const coreEndpointInventory = [
    ["getDashConfig", "GET", "/dash/config"],
    ["getDashValidate", "GET", "/dash/validate"],
    ["dashExecuteAdapter", "POST", "/dash/execute-adapter"],
    ["getDashUsers", "GET", "/dash/list-users"],
    ["exportDashUsers", "GET", "/dash/export-users"],
    ["createDashUser", "POST", "/dash/create-user"],
    ["deleteDashUser", "POST", "/dash/delete-user"],
    ["deleteManyDashUsers", "POST", "/dash/delete-many-users"],
    ["getDashUser", "GET", "/dash/user"],
    ["getDashUserOrganizations", "GET", "/dash/user-organizations"],
    ["updateDashUser", "POST", "/dash/update-user"],
    ["unlinkDashAccount", "POST", "/dash/unlink-account"],
    ["setDashPassword", "POST", "/dash/set-password"],
    ["dashRevokeSession", "POST", "/dash/sessions/revoke"],
    ["dashRevokeAllSessions", "POST", "/dash/sessions/revoke-all"],
    ["dashRevokeManySessions", "POST", "/dash/sessions/revoke-many"],
    ["dashImpersonateUser", "GET", "/dash/impersonate-user"],
    ["dashGetUserStats", "GET", "/dash/user-stats"],
    ["dashGetUserGraphData", "GET", "/dash/user-graph-data"],
    ["dashGetUserRetentionData", "GET", "/dash/user-retention-data"],
    ["dashBanUser", "POST", "/dash/ban-user"],
    ["dashBanManyUsers", "POST", "/dash/ban-many-users"],
    ["dashUnbanUser", "POST", "/dash/unban-user"],
    ["dashSendVerificationEmail", "POST", "/dash/send-verification-email"],
    ["dashSendManyVerificationEmails", "POST", "/dash/send-many-verification-emails"],
    ["dashSendResetPasswordEmail", "POST", "/dash/send-reset-password-email"],
  ];

  test("pins the immutable package and peer runtime", async () => {
    const pkg = await packageJson("@better-auth/infra");
    const lock = await packageLock();
    const locked = lock.packages["node_modules/@better-auth/infra"];

    expect(pkg.version).toBe("0.4.3");
    expect(locked.resolved).toBe(
      "https://registry.npmjs.org/@better-auth/infra/-/infra-0.4.3.tgz",
    );
    expect(locked.integrity).toBe(
      "sha512-wQAdFoFxD/waZYHyF9hKIf8jAnWxVK0R2S28Q/4vCrXWCDKBn5ZVZb1Sy8UHcmbnr1p7xuscBZJTPoFfE6y89A==",
    );
    expect({ sha1: "f20fabec398194cae23ccc35c324eccf8796e4db" }).toEqual({
      sha1: "f20fabec398194cae23ccc35c324eccf8796e4db",
    });
    expect((await packageJson("better-auth")).version).toBe("1.7.1");
    expect((await packageJson("@better-fetch/fetch")).version).toBe("1.3.1");
  });

  test("resolves exact falsey URL/key and nullish timeout/retry defaults", () => {
    const defaults = dash().options;
    expect(defaults).toMatchObject({
      apiUrl: "https://dash.better-auth.com",
      kvUrl: "https://kv.better-auth.com",
      apiKey: "",
      apiOptions: { timeout: 3000 },
      kvOptions: {
        timeout: 1000,
        retry: { attempts: 2, baseDelay: 400, maxDelay: 600 },
      },
    });

    const zeroes = dash({
      apiUrl: "",
      kvUrl: "",
      apiKey: "",
      apiOptions: { timeout: 0 },
      apiTimeout: 9,
      kvOptions: {
        timeout: 0,
        retry: { attempts: 0, baseDelay: 0, maxDelay: 0 },
      },
      kvTimeout: 8,
    });
    expect(zeroes.id).toBe("dash");
    expect(zeroes.version).toBe("0.4.3");
    expect(zeroes.options).toMatchObject({
      apiUrl: "https://dash.better-auth.com",
      kvUrl: "https://kv.better-auth.com",
      apiKey: "",
      apiOptions: { timeout: 0 },
      kvOptions: {
        timeout: 0,
        retry: { attempts: 0, baseDelay: 0, maxDelay: 0 },
      },
    });
  });

  test("pins the private JWT, client, and identification boundary", async () => {
    const source = [
      await infraText("dist/index.mjs"),
      await infraText("dist/crypto-SmxL66Tk.mjs"),
    ].join("\n");
    for (const fragment of [
      '"user-agent": INFRA_USER_AGENT',
      '"x-api-key": options.apiKey',
      'if (options.apiKey) headers["x-api-key"] = options.apiKey',
      'const JWKS_CACHE_TTL_MS = 9e5',
      'jwtVerify(jwsFromHeader, remoteJWKs, { maxTokenAge: "5m" })',
      'Date.now() - issuedAt < JTI_CHECK_GRACE_PERIOD_SECONDS * 1e3',
      '"/api/auth/check-jti"',
      'const IDENTIFICATION_COOKIE_NAME = "__infra-rid"',
      'const CACHE_TTL_MS = 6e4',
      'const CACHE_MAX_SIZE = 1e3',
    ]) {
      expect(source).toContain(fragment);
    }
  });

  test("installs identification as one global hook without owning its route", () => {
    const plugin = dash();
    expect(plugin.hooks.before).toHaveLength(1);
    expect(plugin.hooks.after).toHaveLength(4);
    expect(Object.values(plugin.endpoints).map((endpoint) => endpoint.path)).not.toContain(
      "/identify/:requestId",
    );
  });

  test("contributes activity storage only when explicitly enabled", () => {
    expect(dash().schema).toEqual({});
    expect(dash({ activityTracking: { enabled: true, updateInterval: 0 } }).schema).toEqual({
      user: {
        fields: {
          lastActiveAt: { type: "date", required: false },
        },
      },
    });
  });

  test("publishes the exact 26 core route descriptors with a 10/16 split", () => {
    const endpoints = dash().endpoints;
    const actual = coreEndpointInventory.map(([key]) => [
      key,
      endpoints[key]?.options.method,
      endpoints[key]?.path,
    ]);
    expect(actual).toEqual(coreEndpointInventory);
    expect(actual.filter(([, method]) => method === "GET")).toHaveLength(10);
    expect(actual.filter(([, method]) => method === "POST")).toHaveLength(16);
    expect(new Set(actual.map(([, , path]) => path)).size).toBe(26);
  });

  test("publishes the exact event-query descriptors, constants, and schemas", () => {
    const endpoints = dash().endpoints;
    expect([
      ["getUserEvents", endpoints.getUserEvents.options.method, endpoints.getUserEvents.path],
      ["getAuditLogs", endpoints.getAuditLogs.options.method, endpoints.getAuditLogs.path],
      ["getAllAuditLogs", endpoints.getAllAuditLogs.options.method, endpoints.getAllAuditLogs.path],
      ["getEventTypes", endpoints.getEventTypes.options.method, endpoints.getEventTypes.path],
    ]).toEqual([
      ["getUserEvents", "GET", "/events/list"],
      ["getAuditLogs", "GET", "/events/audit-logs"],
      ["getAllAuditLogs", "GET", "/events/all-audit-logs"],
      ["getEventTypes", "GET", "/events/types"],
    ]);
    expect(Object.keys(USER_EVENT_TYPES)).toHaveLength(39);
    expect(USER_EVENT_TYPES).toMatchObject({
      USER_CREATED: "user_created",
      EMAIL_CHANGED: "email_changed",
      TWO_FACTOR_VERIFIED: "two_factor_verified",
      ORGANIZATION_MEMBER_INVITE_CANCELED: "organization_member_invite_canceled",
      ORGANIZATION_TEAM_MEMBER_REMOVED: "organization_team_member_removed",
    });

    expect(endpoints.getUserEvents.options.query.parse({ limit: "12.5", offset: "-2" }))
      .toEqual({ limit: 12.5, offset: -2 });
    expect(endpoints.getAuditLogs.options.query.parse({ limit: 8, userId: "user-1" }))
      .toEqual({ limit: 8, userId: "user-1" });
    expect(endpoints.getAllAuditLogs.options.query.safeParse({
      organizationId: "org-1",
      userId: "user-1",
    }).error.issues[0].message).toBe("Provide at most one of userId and organizationId.");
    expect(endpoints.getAllAuditLogs.options.query.parse({
      organizationId: " ",
      userId: "user-1",
      unknown: "stripped",
    })).toEqual({ organizationId: " ", userId: "user-1" });
  });

  test("dashClient exposes exactly two nested GET actions and resolver precedence", async () => {
    const fetch = vi.fn(async () => ({ data: { events: [], total: 0, limit: 50, offset: 0 }, error: null }));
    const resolver = vi.fn(() => "resolved-user");
    const client = dashClient({ resolveUserId: resolver });
    const actions = client.getActions(fetch).dash;

    expect(client.id).toBe("dash");
    expect(Object.keys(client.getActions(fetch))).toEqual(["dash"]);
    expect(Object.keys(actions)).toEqual(["getAuditLogs", "getAllAuditLogs"]);
    expect(client.pathMethods).toEqual({
      "/events/audit-logs": "GET",
      "/events/all-audit-logs": "GET",
    });

    await actions.getAuditLogs({
      limit: 4,
      organizationId: "org-1",
      identifier: "member@example.com",
      eventType: "organization_member_added",
      userId: "explicit-user",
      user: { id: "input-user" },
      session: { user: { id: "session-user" } },
    });
    expect(resolver).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenLastCalledWith("/events/audit-logs", {
      method: "GET",
      query: {
        limit: 4,
        offset: undefined,
        organizationId: "org-1",
        identifier: "member@example.com",
        eventType: "organization_member_added",
        userId: "explicit-user",
      },
    });

    await actions.getAuditLogs({ user: { id: "input-user" }, session: { user: { id: "session-user" } } });
    expect(resolver).toHaveBeenLastCalledWith({
      userId: undefined,
      user: { id: "input-user" },
      session: { user: { id: "session-user" } },
    });
    expect(fetch.mock.calls.at(-1)[1].query.userId).toBe("resolved-user");

    await actions.getAllAuditLogs();
    expect(fetch).toHaveBeenLastCalledWith("/events/all-audit-logs", {
      method: "GET",
      query: {
        limit: undefined,
        offset: undefined,
        organizationId: undefined,
        userId: undefined,
        eventType: undefined,
        identifier: undefined,
      },
    });
  });

  test("pins exposed query and body coercion, defaults, and strict unions", () => {
    const endpoints = dash().endpoints;
    expect(
      endpoints.getDashUsers.options.query.parse({
        limit: "12.5",
        offset: "-2",
        where: '[{"field":"email","operator":"contains","value":"@"}]',
        countWhere: "{}",
      }),
    ).toEqual({
      limit: 12.5,
      offset: -2,
      where: [{ field: "email", operator: "contains", value: "@" }],
      countWhere: [],
    });
    expect(
      endpoints.dashGetUserGraphData.options.query.parse({}),
    ).toEqual({ period: "daily" });
    expect(
      endpoints.dashGetUserRetentionData.options.query.parse({}),
    ).toEqual({ period: "weekly" });
    expect(
      endpoints.getDashUser.options.query.parse({ minimal: "false" }),
    ).toEqual({ minimal: false });
    expect(
      endpoints.dashBanUser.options.body.parse({}),
    ).toEqual({ deleteAllSessions: true });
    expect(
      endpoints.setDashPassword.options.body.safeParse({ password: "1234567" }).success,
    ).toBe(false);

    const adapter = endpoints.dashExecuteAdapter.options.body;
    expect(
      adapter.parse({
        action: "findOne",
        model: "user",
        where: [{ field: "id", value: "u1", operator: "eq", connector: "AND" }],
        select: ["id"],
        join: { session: true },
      }),
    ).toEqual({
      action: "findOne",
      model: "user",
      where: [{ field: "id", value: "u1", operator: "eq", connector: "AND" }],
      select: ["id"],
      join: { session: true },
    });
    expect(adapter.safeParse({ action: "delete", model: "user" }).success).toBe(false);
    expect(
      adapter.safeParse({
        action: "findMany",
        model: "user",
        where: [{ field: "id", value: "u1", operator: "not_in" }],
      }).success,
    ).toBe(false);
  });

  test("pins the endpoint authorization, redaction, export, and activity contracts", async () => {
    const source = await infraText("dist/index.mjs");
    for (const fragment of [
      'createAuthEndpoint("/dash/validate",',
      "use: [jwtValidateMiddleware(options)]",
      "use: [jwtMiddleware(options, getUserDetailsJwtSchema)]",
      "return redactDashSettings({",
      "secretEntropy: ctx.context.secret === \"better-auth-secret-12345678901234567890\"",
      "const batchSize = options?.batchSize || 1e4",
      "const staleMs = options?.staleMs || 3e5",
      '"Content-Type": "application/x-ndjson"',
      "updateInterval: options?.activityTracking?.updateInterval ?? 3e5",
      "if (activityUpdateInterval === 0) return",
      'matcher: (ctx) => ctx.request?.method !== "GET"',
      "const { token: _token, ...rest } = session",
    ]) {
      expect(source).toContain(fragment);
    }
  });
});
