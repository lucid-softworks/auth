import { describe, expect, test, vi } from "vitest";
import {
  authServer,
  authOrigin,
  fakeDub,
  install,
  responseBody,
  signUp,
  user,
} from "./helpers.mjs";

function directContext(cookie) {
  const setCookie = vi.fn();
  return {
    context: {
      getCookie: vi.fn(name => name === "dub_id" ? cookie : undefined),
      setCookie,
    },
    setCookie,
  };
}

describe("@dub/better-auth@0.0.6 lead lifecycle oracle", () => {
  test("maps the exact default lead payload and truthy event-name fallback", async () => {
    for (const [leadEventName, expected] of [
      [undefined, "Sign Up"],
      ["", "Sign Up"],
      ["Registered", "Registered"],
    ]) {
      const dubClient = fakeDub();
      const { hook } = install({ dubClient, pluginOptions: { leadEventName } });
      const { context, setCookie } = directContext("click_1");
      await hook(user, context);
      expect(dubClient.track.lead).toHaveBeenCalledWith({
        clickId: "click_1",
        customerAvatar: null,
        customerEmail: "ada@example.test",
        customerExternalId: "user_1",
        customerName: "Ada Lovelace",
        eventName: expected,
      });
      expect(setCookie).toHaveBeenCalledWith("dub_id", "", {
        expires: new Date(0),
        maxAge: 0,
      });
    }

    const missingImage = fakeDub();
    const missing = install({ dubClient: missingImage });
    await missing.hook({ ...user, image: undefined }, directContext("click_2").context);
    expect(missingImage.track.lead).toHaveBeenCalledWith(
      expect.objectContaining({ customerAvatar: undefined }),
    );
  });

  test("custom tracking replaces Dub tracking and receives the original context", async () => {
    const customLeadTrack = vi.fn(async () => undefined);
    const { dubClient, hook } = install({ pluginOptions: { customLeadTrack } });
    const { context, setCookie } = directContext("custom_click");
    await hook(user, context);
    expect(customLeadTrack).toHaveBeenCalledWith(user, context);
    expect(dubClient.track.lead).not.toHaveBeenCalled();
    expect(setCookie).toHaveBeenCalledOnce();
  });

  test("skips absent contexts, absent/empty cookies, and disabled tracking exactly", async () => {
    const absent = install();
    await absent.hook(user, undefined);
    await absent.hook(user, directContext(undefined).context);
    await absent.hook(user, directContext("").context);
    expect(absent.dubClient.track.lead).not.toHaveBeenCalled();

    const customLeadTrack = vi.fn();
    const disabled = install({ pluginOptions: { customLeadTrack, disableLeadTracking: true } });
    const { context, setCookie } = directContext("retained");
    await disabled.hook(user, context);
    expect(customLeadTrack).not.toHaveBeenCalled();
    expect(disabled.dubClient.track.lead).not.toHaveBeenCalled();
    expect(setCookie).not.toHaveBeenCalled();
  });

  test("swallows a rejected provider, ignores its response, and emits the pathless deletion", async () => {
    const lead = vi.fn(async () => { throw new Error("provider unavailable"); });
    const server = authServer({ dubClient: fakeDub({ lead }) });
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const response = await signUp(server.auth, "provider-rejection", { cookie: "dub_id=click" });
    expect(response.status).toBe(200);
    expect(lead).toHaveBeenCalledOnce();
    expect(response.headers.getSetCookie()).toContain(
      "dub_id=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
    );
    const deletion = response.headers.getSetCookie().find(value => value.startsWith("dub_id="));
    expect(deletion).not.toMatch(/Path|HttpOnly|Secure|SameSite/i);
    expect(server.db.user).toHaveLength(1);
    expect(server.db.account).toHaveLength(1);
    expect(server.db.session).toHaveLength(1);
    expect(errorSpy).toHaveBeenCalled();
    errorSpy.mockRestore();
  });

  test("decodes Better Auth cookies with exact duplicate, quote, case, and malformed behavior", async () => {
    const cases = [
      ["dub_id=encoded%20click", "encoded click", true],
      ["dub_id=%E0%A4%A", "%E0%A4%A", true],
      ["dub_id=%ZZ%20", "%ZZ%20", true],
      ['dub_id="quoted click"', "quoted click", true],
      ["dub_id=first; dub_id=second", "first", true],
      ["dub_id=; dub_id=second", undefined, false],
      ["DUB_ID=case-sensitive", undefined, false],
      ["other=value", undefined, false],
    ];
    for (const [index, [cookie, clickId, deleted]] of cases.entries()) {
      const server = authServer();
      const response = await signUp(server.auth, `cookie-${index}`, { cookie });
      expect(response.status).toBe(200);
      if (clickId === undefined) {
        expect(server.dubClient.track.lead).not.toHaveBeenCalled();
      } else {
        expect(server.dubClient.track.lead).toHaveBeenCalledWith(
          expect.objectContaining({ clickId }),
        );
      }
      expect(response.headers.getSetCookie().some(value => value.startsWith("dub_id=")))
        .toBe(deleted);
    }
  });

  test("runs rejected custom tracking after commit and discards every response cookie", async () => {
    let snapshot;
    const server = authServer({
      pluginOptions: {
        customLeadTrack: vi.fn(async () => {
          snapshot = {
            accounts: server.db.account.length,
            sessions: server.db.session.length,
            users: server.db.user.length,
          };
          throw new Error("custom tracking failed");
        }),
      },
    });
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const response = await signUp(server.auth, "custom-rejection", { cookie: "dub_id=click" });
    expect(response.status).toBe(500);
    expect(await response.text()).toBe("");
    expect(response.headers.getSetCookie()).toEqual([]);
    expect(snapshot).toEqual({ accounts: 1, sessions: 1, users: 1 });
    expect(server.db.account).toHaveLength(1);
    expect(server.db.session).toHaveLength(1);
    expect(server.db.user).toHaveLength(1);

    const retry = await signUp(server.auth, "custom-rejection", { cookie: "dub_id=click" });
    expect(retry.status).toBe(422);
    expect(await responseBody(retry)).toEqual({
      code: "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
      message: "User already exists. Use another email.",
    });
    expect(errorSpy).toHaveBeenCalled();
    errorSpy.mockRestore();
  });

  test("installs one general user-create hook and composes without extra state or surface", async () => {
    const unrelated = { id: "unrelated", endpoints: {} };
    const server = authServer({ beforePlugins: [unrelated] });
    const initialized = server.plugin.init();
    expect(Object.keys(initialized)).toEqual(["options"]);
    expect(Object.keys(initialized.options.databaseHooks)).toEqual(["user"]);
    expect(Object.keys(initialized.options.databaseHooks.user)).toEqual(["create"]);
    expect(Object.keys(initialized.options.databaseHooks.user.create)).toEqual(["after"]);
    expect(initialized.options).not.toHaveProperty("schema");
    expect(server.db).toEqual({ account: [], session: [], user: [], verification: [] });

    const { context } = directContext("admin-created");
    context.request = new Request(`${authOrigin}/api/auth/admin/create-user`, { method: "POST" });
    await server.hook(user, context);
    expect(server.dubClient.track.lead).toHaveBeenCalledWith(
      expect.objectContaining({ clickId: "admin-created" }),
    );
  });
});
