import { readFile } from "node:fs/promises";
import { afterEach, vi } from "vitest";

const savedApiUrl = process.env.BETTER_AUTH_API_URL;
process.env.BETTER_AUTH_API_URL = "https://env-sms.example.test/env-base";

export const infraRoot = await import("@better-auth/infra");

if (savedApiUrl === undefined) {
  delete process.env.BETTER_AUTH_API_URL;
} else {
  process.env.BETTER_AUTH_API_URL = savedApiUrl;
}

export const envApiBase = "https://env-sms.example.test/env-base/api";

export function jsonResponse(value, init = {}) {
  return new Response(JSON.stringify(value), {
    headers: { "content-type": "application/json" },
    ...init,
  });
}

export function captureFetch(handler = () => jsonResponse({})) {
  const requests = [];
  const fetch = vi.fn(async (input, init = {}) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const text = request.body ? await request.clone().text() : null;
    requests.push({
      body: text ? JSON.parse(text) : undefined,
      headers: Object.fromEntries(request.headers),
      method: request.method,
      signal: init.signal,
      url: request.url,
    });
    return handler(request, init, requests.length - 1);
  });
  vi.stubGlobal("fetch", fetch);
  return { fetch, requests };
}

export async function packageJson(name) {
  return JSON.parse(await readFile(
    new URL(`node_modules/${name}/package.json`, import.meta.url),
    "utf8",
  ));
}

export async function packageLock() {
  return JSON.parse(await readFile(new URL("package-lock.json", import.meta.url), "utf8"));
}

export function infraText(path) {
  return readFile(
    new URL(`node_modules/@better-auth/infra/${path}`, import.meta.url),
    "utf8",
  );
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  delete process.env.BETTER_AUTH_API_KEY;
});
