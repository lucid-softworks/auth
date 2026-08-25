import { readFile } from "node:fs/promises";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { dubAnalytics } from "@dub/better-auth";
import { vi } from "vitest";

export const authOrigin = "https://auth.example.test";
export const authBaseURL = `${authOrigin}/api/auth`;
export const authSecret = "d".repeat(32);

export const user = {
  email: "ada@example.test",
  emailVerified: false,
  id: "user_1",
  image: null,
  name: "Ada Lovelace",
};

export function fakeDub(overrides = {}) {
  return {
    track: {
      lead: overrides.lead ?? vi.fn(async () => ({ event: "lead" })),
    },
  };
}

export function emptyDatabase() {
  return { account: [], session: [], user: [], verification: [] };
}

export function install(options = {}) {
  const dubClient = options.dubClient ?? fakeDub();
  const plugin = dubAnalytics({ dubClient, ...options.pluginOptions });
  return {
    dubClient,
    hook: plugin.init().options.databaseHooks.user.create.after,
    plugin,
  };
}

export function authServer(options = {}) {
  const db = options.db ?? emptyDatabase();
  const installed = install(options);
  const auth = betterAuth({
    advanced: { disableOriginCheck: false },
    baseURL: authOrigin,
    database: memoryAdapter(db),
    emailAndPassword: { enabled: true },
    logger: { disabled: true },
    plugins: [
      ...(options.beforePlugins ?? []),
      installed.plugin,
      ...(options.afterPlugins ?? []),
    ],
    secret: authSecret,
    trustedOrigins: [authOrigin, "https://app.example.test"],
  });
  return { ...installed, auth, db };
}

export async function request(auth, path, init = {}) {
  return auth.handler(new Request(`${authBaseURL}${path}`, init));
}

export async function postJson(auth, path, body, headers = {}) {
  return request(auth, path, {
    body: JSON.stringify(body),
    headers: { "content-type": "application/json", ...headers },
    method: "POST",
  });
}

export async function signUp(auth, identity, headers = {}) {
  return postJson(auth, "/sign-up/email", {
    email: `${identity}@example.test`,
    name: `Dub ${identity}`,
    password: "correct horse battery staple",
  }, { origin: authOrigin, ...headers });
}

export async function responseBody(response) {
  const body = await response.text();
  return body ? JSON.parse(body) : null;
}

export async function packageJson(name, nestedPath = "") {
  const prefix = nestedPath ? `${nestedPath}/node_modules/` : "";
  return JSON.parse(await readFile(
    new URL(`../node_modules/${prefix}${name}/package.json`, import.meta.url),
    "utf8",
  ));
}

export async function packageLock() {
  return JSON.parse(await readFile(new URL("../package-lock.json", import.meta.url), "utf8"));
}

export async function packageText(path) {
  return readFile(new URL(`../node_modules/@dub/better-auth/${path}`, import.meta.url), "utf8");
}
