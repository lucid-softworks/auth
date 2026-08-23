import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { createAuthClient } from "better-auth/client";
import {
  adminClient,
  anonymousClient,
  magicLinkClient,
  twoFactorClient,
  usernameClient,
} from "better-auth/client/plugins";
import { passkeyClient } from "@better-auth/passkey/client";
import { apiKeyClient } from "@better-auth/api-key/client";
import { base32 } from "@better-auth/utils/base32";
import { createOTP } from "@better-auth/utils/otp";
import { installVirtualAuthenticator } from "./virtual-authenticator.mjs";

const repository = fileURLToPath(new URL("..", import.meta.url));
const betterAuthPackage = JSON.parse(
  await readFile(new URL("node_modules/better-auth/package.json", import.meta.url)),
);
const passkeyPackage = JSON.parse(
  await readFile(
    new URL("node_modules/@better-auth/passkey/package.json", import.meta.url),
  ),
);
const apiKeyPackage = JSON.parse(
  await readFile(
    new URL("node_modules/@better-auth/api-key/package.json", import.meta.url),
  ),
);
const nativePluginClient = {
  id: "lucid-native-conformance",
  version: "1.0.0",
  $InferServerPlugin: {},
  pathMethods: { "/native-plugin/ping": "GET" },
};

class BrowserTransport {
  constructor(origin) {
    this.origin = origin;
    this.cookies = new Map();
    this.requests = [];
  }

  async fetch(input, init = {}) {
    const rawUrl =
      input instanceof URL
        ? input.href
        : input instanceof Request
          ? input.url
          : String(input);
    const url = new URL(rawUrl);
    const headers = new Headers(init.headers);
    if (this.cookies.size > 0) {
      headers.set(
        "cookie",
        [...this.cookies].map(([name, value]) => `${name}=${value}`).join("; "),
      );
    }
    headers.set("origin", this.origin);
    const method = (init.method ?? "GET").toUpperCase();
    const body = typeof init.body === "string" ? JSON.parse(init.body) : null;
    this.requests.push({ method, pathname: url.pathname, search: url.search, body });

    const response = await fetch(input, { ...init, headers });
    for (const cookie of response.headers.getSetCookie()) {
      const [pair, ...attributes] = cookie.split(";");
      const separator = pair.indexOf("=");
      const name = pair.slice(0, separator);
      const value = pair.slice(separator + 1);
      const removed = attributes.some((attribute) =>
        /^\s*max-age=0\s*$/i.test(attribute),
      );
      if (removed || value.length === 0) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    return response;
  }

  async useFixtureSession(authenticationMethod) {
    const response = await this.fetch(
      `${this.origin}/__conformance__/session/${authenticationMethod}`,
      { method: "POST" },
    );
    assert.equal(response.status, 200);
  }

  clearCookies() {
    this.cookies.clear();
  }

  assertRequest(pathname, method, body = undefined) {
    const request = this.requests.findLast(
      (candidate) => candidate.pathname === pathname && candidate.method === method,
    );
    assert.ok(request, `${method} ${pathname} was not sent`);
    if (body !== undefined) assert.deepEqual(request.body, body);
    return request;
  }
}

function success(result, method) {
  assert.equal(result.error, null, `${method}: ${JSON.stringify(result.error)}`);
  assert.notEqual(result.data, null, `${method}: missing data`);
  return result.data;
}

async function runCase(name, callback) {
  try {
    await callback();
    console.log(`ok - ${name}`);
  } catch (error) {
    error.message = `${name}: ${error.message}`;
    throw error;
  }
}

async function conformance(origin) {
  installVirtualAuthenticator(origin);
  const transport = new BrowserTransport(origin);
  const client = createAuthClient({
    baseURL: origin,
    fetchOptions: { customFetchImpl: transport.fetch.bind(transport) },
    plugins: [
      usernameClient(),
      anonymousClient(),
      adminClient(),
      twoFactorClient(),
      passkeyClient(),
      apiKeyClient(),
      magicLinkClient(),
      nativePluginClient,
    ],
  });

  await runCase("Better Auth 1.7.1 baseline", async () => {
    assert.equal(betterAuthPackage.version, "1.7.1");
    assert.equal(passkeyPackage.version, betterAuthPackage.version);
    assert.equal(apiKeyPackage.version, betterAuthPackage.version);
    const response = await transport.fetch(`${origin}/__conformance__/version`);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { betterAuth: betterAuthPackage.version });
    const plugins = await transport.fetch(`${origin}/__conformance__/plugins`);
    assert.equal(plugins.status, 200);
    const metadata = await plugins.json();
    const nativePlugin = metadata.find((plugin) => plugin.id === "conformance");
    const magicLink = metadata.find((plugin) => plugin.id === "magic-link");
    const apiKey = metadata.find((plugin) => plugin.id === "api-key");
    const anonymous = metadata.find((plugin) => plugin.id === "anonymous");
    const username = metadata.find((plugin) => plugin.id === "username");
    assert.equal(nativePlugin.client.betterAuthVersion, betterAuthPackage.version);
    assert.equal(nativePlugin.endpoints[0].clientMethod, "nativePlugin.ping");
    assert.equal(magicLink.client.factory, "magicLinkClient");
    assert.equal(apiKey.client.factory, "apiKeyClient");
    assert.equal(anonymous.client.factory, "anonymousClient");
    assert.equal(username.client.factory, "usernameClient");
  });

  await runCase("native plugin client metadata and route", async () => {
    const data = success(await client.nativePlugin.ping(), "nativePlugin.ping");
    assert.deepEqual(data, {
      plugin: "conformance",
      betterAuth: betterAuthPackage.version,
    });
    transport.assertRequest("/api/auth/native-plugin/ping", "GET");
  });

  await runCase("core email and password clients", async () => {
    const signedUp = success(
      await client.signUp.email({
        name: "Email User",
        email: "Email.User@Example.com",
        password: "correct horse battery staple",
        image: "https://example.com/email-user.png",
        callbackURL: "/verify-email",
      }),
      "signUp.email",
    );
    assert.equal(signedUp.user.email, "email.user@example.com");
    assert.equal(signedUp.user.image, "https://example.com/email-user.png");
    assert.equal(typeof signedUp.token, "string");
    transport.assertRequest("/api/auth/sign-up/email", "POST", {
      name: "Email User",
      email: "Email.User@Example.com",
      password: "correct horse battery staple",
      image: "https://example.com/email-user.png",
      callbackURL: "/verify-email",
    });

    const verified = success(
      await client.$fetch("/verify-password", {
        method: "POST",
        body: { password: "correct horse battery staple" },
      }),
      "verifyPassword",
    );
    assert.equal(verified.status, true);
    transport.assertRequest("/api/auth/verify-password", "POST", {
      password: "correct horse battery staple",
    });

    success(await client.signOut(), "signOut after email signup");
    const signedIn = success(
      await client.signIn.email({
        email: "EMAIL.USER@example.com",
        password: "correct horse battery staple",
        callbackURL: "/dashboard",
        rememberMe: false,
      }),
      "signIn.email",
    );
    assert.equal(signedIn.user.email, "email.user@example.com");
    assert.equal(signedIn.redirect, true);
    assert.equal(signedIn.url, "/dashboard");
    assert.equal(signedIn.twoFactorRedirect, undefined);
    assert.equal(signedIn.twoFactorMethods, undefined);
    assert.equal(signedIn.mfaSetupRequired, undefined);
    transport.assertRequest("/api/auth/sign-in/email", "POST", {
      email: "EMAIL.USER@example.com",
      password: "correct horse battery staple",
      callbackURL: "/dashboard",
      rememberMe: false,
    });

    const rejected = await client.signIn.email({
      email: "missing@example.com",
      password: "wrong password",
    });
    assert.equal(rejected.data, null);
    assert.equal(rejected.error?.status, 401);
    assert.equal(rejected.error?.code, "INVALID_EMAIL_OR_PASSWORD");
    success(await client.signOut(), "signOut after email signin");
  });

  await runCase("email verification clients", async () => {
    const sent = success(
      await client.sendVerificationEmail({
        email: "email.user@example.com",
        callbackURL: "/verified",
      }),
      "sendVerificationEmail",
    );
    assert.equal(sent.status, true);
    transport.assertRequest("/api/auth/send-verification-email", "POST", {
      email: "email.user@example.com",
      callbackURL: "/verified",
    });
    const captured = await transport.fetch(
      `${origin}/__conformance__/verification-token/email.user%40example.com`,
    );
    assert.equal(captured.status, 200);
    const { token } = await captured.json();
    const verified = success(
      await client.verifyEmail({ query: { token } }),
      "verifyEmail",
    );
    assert.equal(verified.status, true);
    assert.equal(verified.user, null);
    const session = success(await client.getSession(), "verified getSession");
    assert.equal(session.user.emailVerified, true);

    const replay = await client.verifyEmail({ query: { token } });
    assert.equal(replay.data, null);
    assert.equal(replay.error?.status, 401);
    assert.equal(replay.error?.code, "INVALID_TOKEN");
    success(await client.signOut(), "signOut after email verification");

    success(
      await client.signUp.email({
        name: "Changed Email",
        email: "change-source@example.com",
        password: "correct horse battery staple",
      }),
      "signUp.email for changeEmail",
    );
    const changed = success(
      await client.changeEmail({
        newEmail: "change-target@example.com",
        callbackURL: "/changed",
      }),
      "changeEmail",
    );
    assert.equal(changed.status, true);
    transport.assertRequest("/api/auth/change-email", "POST", {
      newEmail: "change-target@example.com",
      callbackURL: "/changed",
    });
    const changeCaptured = await transport.fetch(
      `${origin}/__conformance__/verification-token/change-target%40example.com`,
    );
    assert.equal(changeCaptured.status, 200);
    const changeToken = (await changeCaptured.json()).token;
    const changedVerification = success(
      await client.verifyEmail({ query: { token: changeToken } }),
      "verifyEmail after changeEmail",
    );
    assert.equal(changedVerification.user.email, "change-target@example.com");
    assert.equal(changedVerification.user.emailVerified, true);
    success(await client.signOut(), "signOut after changeEmail");
  });

  await runCase("password reset clients", async () => {
    const requested = success(
      await client.requestPasswordReset({
        email: "email.user@example.com",
        redirectTo: "/choose-password",
      }),
      "requestPasswordReset",
    );
    assert.equal(requested.status, true);
    transport.assertRequest("/api/auth/request-password-reset", "POST", {
      email: "email.user@example.com",
      redirectTo: "/choose-password",
    });
    const captured = await transport.fetch(
      `${origin}/__conformance__/password-reset-token/email.user%40example.com`,
    );
    assert.equal(captured.status, 200);
    const { token } = await captured.json();
    const reset = success(
      await client.resetPassword({
        newPassword: "replacement horse battery staple",
        token,
      }),
      "resetPassword",
    );
    assert.equal(reset.status, true);
    transport.assertRequest("/api/auth/reset-password", "POST", {
      newPassword: "replacement horse battery staple",
      token,
    });
    const replay = await client.resetPassword({
      newPassword: "another replacement password",
      token,
    });
    assert.equal(replay.data, null);
    assert.equal(replay.error?.status, 400);
    assert.equal(replay.error?.code, "INVALID_TOKEN");

    const signedIn = success(
      await client.signIn.email({
        email: "email.user@example.com",
        password: "replacement horse battery staple",
      }),
      "signIn.email after password reset",
    );
    assert.equal(signedIn.user.email, "email.user@example.com");
    success(await client.signOut(), "signOut after password reset");
  });

  await runCase("username and session clients", async () => {
    const available = success(
      await client.isUsernameAvailable({ username: "available_user" }),
      "isUsernameAvailable",
    );
    assert.equal(available.available, true);
    transport.assertRequest("/api/auth/is-username-available", "POST", {
      username: "available_user",
    });

    const signedUp = success(
      await client.signUp.email({
        name: "Username User",
        email: "username-user@example.com",
        password: "correct horse battery staple",
        username: "Mixed_User",
        displayUsername: "Mixed User",
      }),
      "signUp.email with username",
    );
    assert.equal(signedUp.user.username, "mixed_user");
    assert.equal(signedUp.user.displayUsername, "Mixed User");
    transport.assertRequest("/api/auth/sign-up/email", "POST", {
      name: "Username User",
      email: "username-user@example.com",
      password: "correct horse battery staple",
      username: "Mixed_User",
      displayUsername: "Mixed User",
    });

    const updated = success(
      await client.updateUser({
        name: "Renamed Profile",
        image: null,
        username: "Renamed_User",
        displayUsername: "Renamed User",
        timezone: "Europe/London",
      }),
      "updateUser username",
    );
    assert.equal(updated.status, true);
    transport.assertRequest("/api/auth/update-user", "POST", {
      name: "Renamed Profile",
      image: null,
      username: "Renamed_User",
      displayUsername: "Renamed User",
      timezone: "Europe/London",
    });
    const sessionUpdate = success(
      await client.updateSession({ theme: "dark" }),
      "updateSession additional field",
    );
    assert.equal(sessionUpdate.session.theme, "dark");
    transport.assertRequest("/api/auth/update-session", "POST", { theme: "dark" });
    const updatedSession = success(
      await client.getSession(),
      "getSession after username update",
    );
    assert.equal(updatedSession.user.username, "renamed_user");
    assert.equal(updatedSession.user.displayUsername, "Renamed User");
    assert.equal(updatedSession.user.name, "Renamed Profile");
    assert.equal(updatedSession.user.image, null);
    assert.equal(updatedSession.user.timezone, "Europe/London");
    assert.equal(updatedSession.session.theme, "dark");
    success(await client.signOut(), "signOut after username update");

    const normalizedSignIn = success(
      await client.signIn.username({
        username: "RENAMED_USER",
        password: "correct horse battery staple",
      }),
      "signIn.username normalized",
    );
    assert.equal(normalizedSignIn.user.username, "renamed_user");
    success(await client.signOut(), "signOut after normalized username signin");

    const signedIn = success(
      await client.signIn.username({
        username: "luna",
        password: "correct horse battery staple",
        callbackURL: "/dashboard",
      }),
      "signIn.username",
    );
    assert.equal(signedIn.user.username, "luna");
    assert.equal(signedIn.redirect, true);
    assert.equal(signedIn.url, "/dashboard");
    transport.assertRequest("/api/auth/sign-in/username", "POST", {
      username: "luna",
      password: "correct horse battery staple",
      callbackURL: "/dashboard",
    });

    const session = success(await client.getSession(), "getSession");
    assert.equal(session.user.username, "luna");
    assert.equal(session.session.assurance, undefined);
    assert.equal(session.session.stepUpRequired, undefined);
    transport.assertRequest("/api/auth/get-session", "GET");

    const rejected = await client.signIn.username({
      username: "luna",
      password: "wrong password",
    });
    assert.equal(rejected.data, null);
    assert.equal(rejected.error?.status, 401);
    assert.equal(rejected.error?.code, "INVALID_USERNAME_OR_PASSWORD");
  });

  await runCase("admin client", async () => {
    const administrator = success(await client.getSession(), "admin getSession");
    const created = success(
      await client.admin.createUser({
        email: "casey@example.com",
        password: "temporary password",
        name: "Casey",
        role: "member",
        data: { username: "casey", department: "support" },
      }),
      "admin.createUser",
    );
    assert.equal(created.user.username, "casey");
    assert.equal(created.user.department, "support");
    assert.equal(created.user.mustChangePassword, undefined);
    transport.assertRequest("/api/auth/admin/create-user", "POST", {
      email: "casey@example.com",
      password: "temporary password",
      name: "Casey",
      role: "member",
      data: { username: "casey", department: "support" },
    });

    const passwordless = success(
      await client.admin.createUser({
        email: "taylor@example.com",
        name: "Taylor",
        data: { username: "taylor" },
      }),
      "admin.createUser passwordless",
    );
    assert.equal(passwordless.user.role, "user");
    const dataRole = success(
      await client.admin.createUser({
        email: "river@example.com",
        name: "River",
        data: { username: "river", role: ["member", "viewer"] },
      }),
      "admin.createUser data role",
    );
    assert.equal(dataRole.user.role, "member,viewer");

    const fetched = success(
      await client.admin.getUser({ query: { id: created.user.id } }),
      "admin.getUser",
    );
    assert.equal(fetched.id, created.user.id);

    const updated = success(
      await client.admin.updateUser({
        userId: created.user.id,
        data: {
          name: "Casey Updated",
          emailVerified: true,
          department: "operations",
        },
      }),
      "admin.updateUser",
    );
    assert.equal(updated.name, "Casey Updated");
    assert.equal(updated.emailVerified, true);
    assert.equal(updated.department, "operations");

    const permission = success(
      await client.admin.hasPermission({ permissions: { user: ["list", "get"] } }),
      "admin.hasPermission",
    );
    assert.equal(permission.success, true);

    const listed = success(
      await client.admin.listUsers({
        query: {
          searchValue: "casey@",
          searchField: "email",
          searchOperator: "starts_with",
          limit: 20,
          offset: 0,
          sortBy: "name",
          sortDirection: "desc",
        },
      }),
      "admin.listUsers",
    );
    assert.equal(listed.total, 1);
    assert.ok(listed.users.some((user) => user.id === created.user.id));
    const listRequest = transport.assertRequest("/api/auth/admin/list-users", "GET");
    assert.match(listRequest.search, /limit=20/);
    const customFiltered = success(
      await client.admin.listUsers({
        query: {
          filterField: "department",
          filterValue: ["operations"],
          filterOperator: "in",
          sortBy: "department",
          sortDirection: "asc",
        },
      }),
      "admin.listUsers custom filter",
    );
    assert.deepEqual(
      customFiltered.users.map((user) => user.id),
      [created.user.id],
    );

    const role = success(
      await client.admin.setRole({
        userId: created.user.id,
        role: ["member", "viewer"],
      }),
      "admin.setRole",
    );
    assert.equal(role.user.role, "member,viewer");

    success(
      await client.admin.setUserPassword({
        userId: created.user.id,
        newPassword: "replacement password",
      }),
      "admin.setUserPassword",
    );
    const banned = success(
      await client.admin.banUser({
        userId: created.user.id,
        banReason: "conformance",
        banExpiresIn: 60,
      }),
      "admin.banUser",
    );
    assert.equal(banned.user.banned, true);
    const unbanned = success(
      await client.admin.unbanUser({ userId: created.user.id }),
      "admin.unbanUser",
    );
    assert.equal(unbanned.user.banned, false);

    const impersonated = success(
      await client.admin.impersonateUser({ userId: created.user.id }),
      "admin.impersonateUser",
    );
    assert.equal(impersonated.user.id, created.user.id);
    assert.equal(impersonated.session.impersonatedBy, administrator.user.id);
    const restored = success(
      await client.admin.stopImpersonating(),
      "admin.stopImpersonating",
    );
    assert.equal(restored.user.id, administrator.user.id);
    const restoredSession = success(
      await client.getSession(),
      "admin restored original session",
    );
    assert.equal(restoredSession.session.id, administrator.session.id);

    await transport.useFixtureSession("password");
    const current = success(await client.getSession(), "admin restored fixture session");
    const sessions = success(
      await client.admin.listUserSessions({ userId: administrator.user.id }),
      "admin.listUserSessions",
    );
    const revocable = sessions.sessions.find(
      (session) => session.id !== current.session.id,
    );
    assert.ok(revocable);
    success(
      await client.admin.revokeUserSession({ sessionToken: revocable.token }),
      "admin.revokeUserSession",
    );
    success(
      await client.admin.revokeUserSessions({ userId: created.user.id }),
      "admin.revokeUserSessions",
    );
    success(
      await client.admin.removeUser({ userId: passwordless.user.id }),
      "admin.removeUser",
    );
    success(
      await client.admin.removeUser({ userId: dataRole.user.id }),
      "admin.removeUser data role",
    );
  });

  await runCase("passkey client", async () => {
    const emptyPasskeys = success(
      await client.passkey.listUserPasskeys(),
      "passkey.listUserPasskeys",
    );
    assert.deepEqual(emptyPasskeys, []);
    transport.assertRequest("/api/auth/passkey/list-user-passkeys", "GET");

    const registration = success(
      await client.passkey.addPasskey({
        name: "Conformance key",
        authenticatorAttachment: "platform",
        context: "official-client",
        createSession: true,
      }),
      "passkey.addPasskey",
    );
    assert.equal(registration.name, "Conformance key");
    assert.equal(registration.deviceType, "singleDevice");
    assert.equal(registration.backedUp, false);
    assert.equal(registration.transports, "internal");
    assert.equal(registration.user.id, registration.userId);
    assert.equal(typeof registration.session.token, "string");
    const options = transport.assertRequest(
      "/api/auth/passkey/generate-register-options",
      "GET",
    );
    assert.match(options.search, /name=Conformance/);
    assert.match(options.search, /authenticatorAttachment=platform/);
    assert.match(options.search, /context=official-client/);
    transport.assertRequest("/api/auth/passkey/verify-registration", "POST");

    const passkeys = success(
      await client.passkey.listUserPasskeys(),
      "passkey.listUserPasskeys registered",
    );
    assert.equal(passkeys.length, 1);
    assert.equal(passkeys[0].credentialID, registration.credentialID);

    const updated = success(
      await client.passkey.updatePasskey({ id: passkeys[0].id, name: "Updated key" }),
      "passkey.updatePasskey",
    );
    assert.equal(updated.passkey.name, "Updated key");
    transport.assertRequest("/api/auth/passkey/update-passkey", "POST", {
      id: passkeys[0].id,
      name: "Updated key",
    });

    transport.clearCookies();
    const authentication = success(
      await client.signIn.passkey(),
      "signIn.passkey",
    );
    assert.equal(authentication.user.id, registration.userId);
    transport.assertRequest(
      "/api/auth/passkey/generate-authenticate-options",
      "GET",
    );
    transport.assertRequest("/api/auth/passkey/verify-authentication", "POST");

    const deleted = success(
      await client.passkey.deletePasskey({ id: passkeys[0].id }),
      "passkey.deletePasskey",
    );
    assert.equal(deleted.status, true);
    transport.assertRequest("/api/auth/passkey/delete-passkey", "POST", {
      id: passkeys[0].id,
    });
  });

  await runCase("complete two-factor client", async () => {
    await transport.useFixtureSession("password");
    const enabled = success(
      await client.twoFactor.enable({
        password: "correct horse battery staple",
        method: "totp",
        issuer: "lucid-auth conformance",
      }),
      "twoFactor.enable totp",
    );
    assert.equal(enabled.method, "totp");
    assert.equal(typeof enabled.totpURI, "string");
    assert.equal(enabled.backupCodes.length, 10);
    transport.assertRequest("/api/auth/two-factor/enable", "POST", {
      password: "correct horse battery staple",
      method: "totp",
      issuer: "lucid-auth conformance",
    });

    const uri = success(
      await client.twoFactor.getTotpUri({
        password: "correct horse battery staple",
      }),
      "twoFactor.getTotpUri",
    );
    assert.equal(typeof uri.totpURI, "string");
    const encodedSecret = new URL(enabled.totpURI).searchParams.get("secret");
    const secret = new TextDecoder().decode(base32.decode(encodedSecret));
    const setupCode = await createOTP(secret, { digits: 6, period: 1 }).totp();
    const setup = success(
      await client.twoFactor.verifyTotp({ code: setupCode, trustDevice: false }),
      "twoFactor.verifyTotp setup",
    );
    assert.equal(setup.user.twoFactorEnabled, true);

    const generated = success(
      await client.twoFactor.generateBackupCodes({
        password: "correct horse battery staple",
      }),
      "twoFactor.generateBackupCodes",
    );
    assert.equal(generated.status, true);
    assert.equal(generated.backupCodes.length, 10);
    transport.assertRequest("/api/auth/two-factor/generate-backup-codes", "POST", {
      password: "correct horse battery staple",
    });

    await new Promise((resolve) => setTimeout(resolve, 1100));
    transport.clearCookies();
    const totpChallenge = success(
      await client.signIn.username({
        username: "luna",
        password: "correct horse battery staple",
      }),
      "signIn.username TOTP challenge",
    );
    assert.equal(totpChallenge.twoFactorRedirect, true);
    assert.deepEqual(totpChallenge.twoFactorMethods, ["totp", "otp"]);
    const signInCode = await createOTP(secret, { digits: 6, period: 1 }).totp();
    const totpVerified = success(
      await client.twoFactor.verifyTotp({ code: signInCode, trustDevice: false }),
      "twoFactor.verifyTotp sign-in",
    );
    assert.equal(totpVerified.user.twoFactorEnabled, true);

    transport.clearCookies();
    success(
      await client.signIn.username({
        username: "luna",
        password: "correct horse battery staple",
      }),
      "signIn.username OTP challenge",
    );
    const sent = success(
      await client.twoFactor.sendOtp({ trustDevice: true }),
      "twoFactor.sendOtp",
    );
    assert.equal(sent.status, true);
    const otpResponse = await transport.fetch(
      `${origin}/__conformance__/two-factor-otp/luna@example.com`,
    );
    assert.equal(otpResponse.status, 200);
    const { code: deliveredCode } = await otpResponse.json();
    const otpVerified = success(
      await client.twoFactor.verifyOtp({
        code: deliveredCode,
        trustDevice: true,
      }),
      "twoFactor.verifyOtp",
    );
    assert.equal(otpVerified.user.twoFactorEnabled, true);
    assert.equal(
      transport.cookies.has("better-auth.trust_device"),
      true,
      `verifyOtp did not set the trust-device cookie: ${JSON.stringify([...transport.cookies.keys()])}`,
    );

    transport.cookies.delete("better-auth.session_token");
    const trusted = success(
      await client.signIn.username({
        username: "luna",
        password: "correct horse battery staple",
      }),
      "signIn.username trusted device",
    );
    assert.equal(trusted.twoFactorRedirect, undefined);
    assert.equal(trusted.user.twoFactorEnabled, true);

    transport.clearCookies();
    success(
      await client.signIn.username({
        username: "luna",
        password: "correct horse battery staple",
      }),
      "signIn.username backup-code challenge",
    );
    const backupVerified = success(
      await client.twoFactor.verifyBackupCode({
        code: generated.backupCodes[0],
        disableSession: false,
        trustDevice: false,
      }),
      "twoFactor.verifyBackupCode",
    );
    assert.equal(typeof backupVerified.token, "string");

    const disabled = success(
      await client.twoFactor.disable({ password: "correct horse battery staple" }),
      "twoFactor.disable",
    );
    assert.equal(disabled.status, true);

    const otpEnabled = success(
      await client.twoFactor.enable({
        password: "correct horse battery staple",
        method: "otp",
      }),
      "twoFactor.enable otp",
    );
    assert.deepEqual(otpEnabled, { method: "otp" });
    success(
      await client.twoFactor.disable({ password: "correct horse battery staple" }),
      "twoFactor.disable otp",
    );
  });

  await runCase("magic-link client", async () => {
    const email = "magic-client@example.com";
    const sent = success(
      await client.signIn.magicLink({
        email,
        name: "Magic Client",
        metadata: { source: "official-client" },
      }),
      "signIn.magicLink",
    );
    assert.deepEqual(sent, { status: true });
    transport.assertRequest("/api/auth/sign-in/magic-link", "POST", {
      email,
      name: "Magic Client",
      metadata: { source: "official-client" },
    });

    const tokenResponse = await transport.fetch(
      `${origin}/__conformance__/magic-link-token/${email}`,
    );
    assert.equal(tokenResponse.status, 200);
    const { token } = await tokenResponse.json();
    const verified = success(
      await client.magicLink.verify({ query: { token } }),
      "magicLink.verify",
    );
    assert.equal(verified.user.email, email);
    assert.equal(verified.user.emailVerified, true);
    assert.equal(typeof verified.token, "string");
    const request = transport.assertRequest("/api/auth/magic-link/verify", "GET");
    assert.equal(new URLSearchParams(request.search).get("token"), token);
    success(await client.signOut(), "signOut after magic link");
  });

  await runCase("API-key client", async () => {
    await transport.useFixtureSession("strong");
    const created = success(
      await client.apiKey.create({
        name: "Official client key",
        prefix: "official_",
        expiresIn: 86_400,
        metadata: { source: "official-client" },
      }),
      "apiKey.create",
    );
    assert.match(created.key, /^official_/);
    assert.equal(created.configId, "default");
    assert.equal(created.metadata.source, "official-client");
    assert.equal(created.permissions.documents[0], "read");
    assert.equal("keyHash" in created, false);
    transport.assertRequest("/api/auth/api-key/create", "POST", {
      name: "Official client key",
      prefix: "official_",
      expiresIn: 86_400,
      metadata: { source: "official-client" },
    });

    const fetched = success(
      await client.apiKey.get({ query: { id: created.id } }),
      "apiKey.get",
    );
    assert.equal(fetched.id, created.id);
    assert.equal("key" in fetched, false);

    const listed = success(
      await client.apiKey.list({
        query: {
          limit: 1,
          offset: 0,
          sortBy: "createdAt",
          sortDirection: "desc",
        },
      }),
      "apiKey.list",
    );
    assert.equal(listed.total, 1);
    assert.equal(listed.apiKeys[0].id, created.id);
    assert.equal("key" in listed.apiKeys[0], false);

    const updated = success(
      await client.apiKey.update({ keyId: created.id, name: "Updated client key" }),
      "apiKey.update",
    );
    assert.equal(updated.name, "Updated client key");

    const verifiedResponse = await transport.fetch(
      `${origin}/api/auth/api-key/verify`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          key: created.key,
          permissions: { documents: ["read"] },
        }),
      },
    );
    assert.equal(verifiedResponse.status, 200);
    const verified = await verifiedResponse.json();
    assert.equal(verified.valid, true);
    assert.equal(verified.error, null);
    assert.equal("key" in verified.key, false);

    transport.clearCookies();
    const sessionResponse = await transport.fetch(`${origin}/api/auth/get-session`, {
      headers: { "x-api-key": created.key },
    });
    assert.equal(sessionResponse.status, 200);
    const session = await sessionResponse.json();
    assert.equal(session.session.id, created.id);
    assert.equal(session.user.email, "luna@example.com");

    await transport.useFixtureSession("strong");
    const deleted = success(
      await client.apiKey.delete({ keyId: created.id }),
      "apiKey.delete",
    );
    assert.equal(deleted.success, true);
  });

  await runCase("anonymous and sign-out clients", async () => {
    success(await client.signOut(), "signOut");
    const anonymous = success(await client.signIn.anonymous(), "signIn.anonymous");
    assert.equal(anonymous.user.isAnonymous, true);
    assert.equal(anonymous.user.role, "user");
    transport.assertRequest("/api/auth/sign-in/anonymous", "POST", {});
    const repeated = await client.signIn.anonymous();
    assert.equal(
      repeated.error?.code,
      "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY",
    );
    const deleted = success(
      await client.deleteAnonymousUser(),
      "deleteAnonymousUser",
    );
    assert.equal(deleted.success, true);
    transport.assertRequest("/api/auth/delete-anonymous-user", "POST", {});

    success(await client.signIn.anonymous(), "signIn.anonymous for email upgrade");
    const upgraded = success(
      await client.signUp.email({
        name: "Anonymous Upgrade",
        email: "anonymous-upgrade@example.com",
        password: "correct horse battery staple",
      }),
      "signUp.email anonymous upgrade",
    );
    assert.equal(upgraded.user.isAnonymous, false);
    const permanentDelete = await client.deleteAnonymousUser();
    assert.equal(permanentDelete.error?.code, "USER_IS_NOT_ANONYMOUS");
    success(await client.signOut(), "signOut after anonymous email upgrade");
  });

  await runCase("core social OAuth client and callback", async () => {
    transport.clearCookies();
    const anonymous = success(
      await client.signIn.anonymous(),
      "signIn.anonymous for social upgrade",
    );
    const social = success(
      await client.signIn.social({
        provider: "conformance-oauth",
        callbackURL: "/oauth/existing",
        newUserCallbackURL: "/oauth/new",
        errorCallbackURL: `${origin}/oauth/error`,
        disableRedirect: true,
        additionalParams: { prompt: "consent" },
      }),
      "signIn.social",
    );
    assert.equal(social.redirect, false);
    const authorize = new URL(social.url);
    assert.equal(authorize.origin, "https://provider.conformance.invalid");
    assert.equal(authorize.searchParams.get("code_challenge_method"), "S256");
    assert.ok(authorize.searchParams.get("nonce"));
    const state = authorize.searchParams.get("state");
    assert.ok(state);
    transport.assertRequest("/api/auth/sign-in/social", "POST", {
      provider: "conformance-oauth",
      callbackURL: "/oauth/existing",
      newUserCallbackURL: "/oauth/new",
      errorCallbackURL: `${origin}/oauth/error`,
      disableRedirect: true,
      additionalParams: { prompt: "consent" },
    });
    const callback = await transport.fetch(
      `${origin}/api/auth/callback/conformance-oauth?code=official-client-code&state=${encodeURIComponent(state)}&iss=${encodeURIComponent("https://issuer.conformance.invalid")}`,
      { redirect: "manual" },
    );
    assert.equal(callback.status, 302);
    assert.equal(callback.headers.get("location"), "/oauth/new");
    const session = success(await client.getSession(), "getSession after social OAuth");
    assert.equal(session.user.email, "official-social@example.com");
    assert.notEqual(session.user.id, anonymous.user.id);
    assert.equal(session.user.image, "https://provider.conformance.invalid/avatar.png");
    success(await client.signOut(), "signOut after social OAuth");
  });

  await runCase("linked account and provider token clients", async () => {
    await transport.useFixtureSession("strong");
    const linked = success(
      await client.linkSocial({
        provider: "conformance-oauth",
        idToken: {
          token: "official-link-id-token",
          nonce: "official-link-nonce",
          accessToken: "official-link-access-token",
          refreshToken: "official-link-refresh-token",
        },
        disableRedirect: true,
      }),
      "linkSocial",
    );
    assert.deepEqual(linked, { url: "", status: true, redirect: false });
    transport.assertRequest("/api/auth/link-social", "POST", {
      provider: "conformance-oauth",
      idToken: {
        token: "official-link-id-token",
        nonce: "official-link-nonce",
        accessToken: "official-link-access-token",
        refreshToken: "official-link-refresh-token",
      },
      disableRedirect: true,
    });

    const accounts = success(await client.listAccounts(), "listAccounts");
    const account = accounts.find(
      (candidate) => candidate.providerId === "conformance-oauth",
    );
    assert.ok(account);
    assert.deepEqual(account.scopes, []);
    assert.equal(account.issuer, "https://issuer.conformance.invalid");
    assert.equal(account.accountId, "official-linked-subject");

    const access = success(
      await client.getAccessToken({ accountId: account.id }),
      "getAccessToken",
    );
    assert.equal(access.accessToken, "official-link-access-token");
    assert.equal(access.idToken, "official-link-id-token");

    const refreshed = success(
      await client.refreshToken({ accountId: account.id }),
      "refreshToken",
    );
    assert.equal(refreshed.accessToken, "official-refreshed-access-token");
    assert.equal(refreshed.refreshToken, "official-refreshed-refresh-token");
    assert.equal(refreshed.providerId, "conformance-oauth");
    assert.equal(refreshed.accountId, account.id);

    const info = success(
      await client.accountInfo({ query: { accountId: account.id } }),
      "accountInfo",
    );
    assert.equal(info.account.id, account.id);
    assert.equal(info.account.accountId, "official-linked-subject");
    assert.equal(info.user.email, "luna@example.com");
    assert.equal(info.data.fixture, "linked-account");

    const unlinked = success(
      await client.unlinkAccount({ accountId: account.id }),
      "unlinkAccount",
    );
    assert.equal(unlinked.status, true);
    const remaining = success(await client.listAccounts(), "listAccounts after unlink");
    assert.ok(
      remaining.every((candidate) => candidate.id !== account.id),
      "unlinked account must no longer be listed",
    );
  });

  await runCase("current-user deletion client", async () => {
    success(
      await client.signUp.email({
        name: "Delete User",
        email: "delete-user@example.com",
        password: "correct horse battery staple",
      }),
      "signUp.email for deleteUser",
    );
    const deleted = success(
      await client.deleteUser({
        password: "correct horse battery staple",
        callbackURL: "/goodbye",
      }),
      "deleteUser",
    );
    assert.deepEqual(deleted, { success: true, message: "User deleted" });
    transport.assertRequest("/api/auth/delete-user", "POST", {
      password: "correct horse battery staple",
      callbackURL: "/goodbye",
    });
    const session = await client.getSession();
    assert.equal(session.data, null);
  });
}

async function startServer() {
  const child = spawn(
    "cargo",
    [
      "run",
      "--quiet",
      "--manifest-path",
      "conformance/server/Cargo.toml",
    ],
    {
      cwd: repository,
      detached: process.platform !== "win32",
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let output = "";
  child.stderr.on("data", (chunk) => {
    output += chunk;
  });
  const origin = await new Promise((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error(`server startup timed out\n${output}`)),
      120_000,
    );
    child.stdout.on("data", (chunk) => {
      output += chunk;
      const match = output.match(/LUCID_AUTH_CONFORMANCE_URL=(http:\/\/[^\s]+)/);
      if (match) {
        clearTimeout(timeout);
        resolve(match[1]);
      }
    });
    child.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.once("exit", (code) => {
      clearTimeout(timeout);
      reject(new Error(`server exited with ${code}\n${output}`));
    });
  });
  return { child, origin };
}

function stopServer(child) {
  if (child.exitCode !== null) return;
  if (process.platform === "win32") child.kill("SIGTERM");
  else process.kill(-child.pid, "SIGTERM");
}

const { child, origin } = await startServer();
try {
  await conformance(origin);
} finally {
  stopServer(child);
}
