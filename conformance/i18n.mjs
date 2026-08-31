import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { APIError, isAPIError } from "better-auth/api";
import { createAuthClient } from "better-auth/client";
import { parseCookies } from "better-auth/cookies";
import * as i18nExports from "@better-auth/i18n";
import { i18n, locales } from "@better-auth/i18n";
import * as i18nClientExports from "@better-auth/i18n/client";
import { i18nClient } from "@better-auth/i18n/client";
import * as localeExports from "@better-auth/i18n/locales";

const packageVersion = "1.7.2";
const catalogLocales = [
  "ar",
  "bn",
  "de",
  "en",
  "es",
  "fa",
  "fr",
  "hi",
  "id",
  "it",
  "ja",
  "ko",
  "nl",
  "pl",
  "pt",
  "ru",
  "sv",
  "th",
  "tr",
  "uk",
  "vi",
  "zh",
];
const catalogDigest =
  "7d5923f4e2989c07f234992317d5e52f9ecc74b11163f4581592d917adb31893";
const catalogBytes = 51_711;

function sortedObject(object) {
  return Object.fromEntries(
    Object.entries(object)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([key, value]) => [
        key,
        typeof value === "object" && value !== null
          ? sortedObject(value)
          : value,
      ]),
  );
}

function returnedError(code = "PROBE", message = "Original message") {
  return new APIError("I'M_A_TEAPOT", {
    cause: "private cause",
    code,
    extra: "discarded",
    message,
  });
}

async function invokeAfter(
  plugin,
  { headers = new Headers(), returned = returnedError(), session } = {},
) {
  const hook = plugin.hooks.after[0];
  try {
    const result = await hook.handler({
      context: { returned, ...(session === undefined ? {} : { session }) },
      headers,
    });
    return { error: null, result };
  } catch (error) {
    assert.equal(isAPIError(error), true, `unexpected hook error: ${error}`);
    return { error, result: undefined };
  }
}

async function selectedLocale({
  callback,
  defaultLocale,
  detection = ["header"],
  header,
  localeCookie,
  session,
  userLocaleField,
}) {
  const plugin = i18n({
    translations: {
      de: { PROBE: "de" },
      en: { PROBE: "en" },
      fr: { PROBE: "fr" },
      zh: { PROBE: "zh" },
    },
    detection,
    ...(defaultLocale === undefined ? {} : { defaultLocale }),
    ...(localeCookie === undefined ? {} : { localeCookie }),
    ...(userLocaleField === undefined ? {} : { userLocaleField }),
    ...(callback === undefined ? {} : { getLocale: callback }),
  });
  const headers =
    header === undefined
      ? new Headers()
      : header instanceof Headers || typeof header?.get === "function"
        ? header
        : new Headers(header);
  const { error } = await invokeAfter(plugin, { headers, session });
  return error?.body?.message ?? null;
}

function exportAndDescriptorConformance() {
  assert.deepEqual(Object.keys(i18nExports).sort(), ["i18n", "locales"]);
  assert.deepEqual(Object.keys(i18nClientExports), ["i18nClient"]);
  assert.deepEqual(Object.keys(localeExports), catalogLocales);
  assert.equal(i18nExports.locales, locales);

  assert.throws(
    () => i18n({ translations: {} }),
    new Error(
      "i18n plugin: translations object is empty. At least one locale must be provided.",
    ),
  );

  const translations = { en: { PROBE: "Translated" } };
  const plugin = i18n({ translations });
  assert.deepEqual(Object.keys(plugin), ["id", "version", "hooks", "options"]);
  assert.equal(plugin.id, "i18n");
  assert.equal(plugin.version, packageVersion);
  assert.equal(plugin.options.translations, translations);
  assert.equal(plugin.options.defaultLocale, "en");
  assert.deepEqual(plugin.options.detection, ["header"]);
  assert.equal(plugin.options.localeCookie, "locale");
  assert.equal(plugin.options.userLocaleField, "locale");
  assert.deepEqual(Object.keys(plugin.hooks), ["after"]);
  assert.equal(plugin.hooks.after.length, 1);
  assert.equal(plugin.hooks.after[0].matcher(), true);
  assert.equal(plugin.hooks.after[0].matcher({ path: "/anything" }), true);
  assert.equal(typeof plugin.hooks.after[0].handler, "function");
  for (const unsupported of [
    "$ERROR_CODES",
    "client",
    "cookies",
    "endpoints",
    "migrations",
    "onRequest",
    "rateLimit",
    "schema",
  ]) {
    assert.equal(unsupported in plugin, false, `${unsupported} must not be advertised`);
  }

  assert.equal(
    i18n({ translations: { fr: { PROBE: "fr" } } }).options.defaultLocale,
    "en",
  );
  assert.equal(
    i18n({
      translations: { fr: { PROBE: "fr" } },
      defaultLocale: "fr",
    }).options.defaultLocale,
    "fr",
  );
  assert.equal(
    i18n({
      translations: { fr: { PROBE: "fr" } },
      defaultLocale: "missing",
    }).options.defaultLocale,
    "missing",
  );
  assert.equal(
    i18n({
      translations: { fr: { PROBE: "fr" } },
      defaultLocale: "",
    }).options.defaultLocale,
    "",
  );

  const client = i18nClient();
  assert.deepEqual(Object.keys(client), ["id", "version", "$InferServerPlugin"]);
  assert.equal(client.id, "i18n");
  assert.equal(client.version, packageVersion);
  assert.deepEqual(client.$InferServerPlugin, {});
  assert.notEqual(i18nClient(), client);
}

async function clientConformance() {
  const requests = [];
  const client = createAuthClient({
    baseURL: "https://i18n.example.test",
    plugins: [i18nClient()],
    fetchOptions: {
      customFetchImpl: async (input, init) => {
        requests.push({ input: String(input), method: init.method });
        return Response.json(
          {
            code: "PROBE",
            message: "Translated",
            originalMessage: "Original message",
          },
          { status: 418 },
        );
      },
    },
  });
  assert.deepEqual(
    Object.keys(client).filter((key) => key.toLowerCase().includes("i18n")),
    [],
  );
  assert.deepEqual(await client.$fetch("/i18n-probe", { method: "GET" }), {
    data: null,
    error: {
      code: "PROBE",
      message: "Translated",
      originalMessage: "Original message",
      status: 418,
      statusText: "",
    },
  });
  assert.deepEqual(requests, [
    {
      input: "https://i18n.example.test/api/auth/i18n-probe",
      method: "GET",
    },
  ]);
}

async function apiErrorConformance() {
  const plugin = i18n({
    translations: { en: { EMPTY: "", PROBE: "Translated", SPACE: " " } },
  });
  const original = returnedError();
  const translated = await invokeAfter(plugin, { returned: original });
  assert.equal(translated.result, undefined);
  assert.notEqual(translated.error, original);
  assert.equal(translated.error.status, "I'M_A_TEAPOT");
  assert.equal(translated.error.statusCode, 418);
  assert.deepEqual(translated.error.body, {
    code: "PROBE",
    message: "Translated",
    originalMessage: "Original message",
  });

  for (const returned of [
    { body: { code: "PROBE", message: "looks like an API error" } },
    Response.json({ code: "PROBE", message: "response-shaped error" }),
    new Error("ordinary error"),
  ]) {
    assert.deepEqual(await invokeAfter(plugin, { returned }), {
      error: null,
      result: undefined,
    });
  }

  for (const returned of [
    new APIError("BAD_REQUEST", { message: "missing code" }),
    new APIError("BAD_REQUEST", { code: 7, message: "numeric code" }),
    returnedError("UNKNOWN"),
    returnedError("EMPTY"),
  ]) {
    assert.deepEqual(await invokeAfter(plugin, { returned }), {
      error: null,
      result: undefined,
    });
  }

  const whitespace = await invokeAfter(plugin, {
    returned: returnedError("SPACE"),
  });
  assert.deepEqual(whitespace.error.body, {
    code: "SPACE",
    message: " ",
    originalMessage: "Original message",
  });

  const noDictionaryFallback = i18n({
    translations: {
      en: { PROBE: "English fallback must not be used" },
      fr: {},
    },
    defaultLocale: "fr",
  });
  assert.deepEqual(await invokeAfter(noDictionaryFallback), {
    error: null,
    result: undefined,
  });

  const unavailableDefault = i18n({
    translations: { fr: { PROBE: "French" } },
    defaultLocale: "missing",
  });
  assert.deepEqual(await invokeAfter(unavailableDefault), {
    error: null,
    result: undefined,
  });
}

async function headerConformance() {
  const cases = [
    [undefined, "en"],
    [{ "accept-language": "fr-CA;q=0.9, en;q=0.8" }, "fr"],
    [{ "accept-language": "en;q=-1, fr;q=0" }, "fr"],
    [{ "accept-language": "en;Q=0.9, fr;q=0.1" }, "en"],
    [{ "accept-language": "en;q=0.1junk, fr;q=0.2" }, "fr"],
    [{ "accept-language": "en;x=0.9;q=0, fr;q=0.1" }, "en"],
    [{ "accept-language": "xx;q=1, fr;q=.5" }, "fr"],
    [{ "accept-language": "zh-Hant-TW" }, "zh"],
    [{ "accept-language": "FR, de" }, "de"],
    [{ "accept-language": " , -US, en " }, "en"],
  ];
  for (const [header, expected] of cases) {
    assert.equal(await selectedLocale({ header }), expected, JSON.stringify(header));
  }
}

async function cookieConformance() {
  const cases = [
    ["locale=fr", "fr"],
    ["locale=%66r", "fr"],
    ['locale="fr"', "fr"],
    ["locale=de; locale=fr", "fr"],
    ["locale=fr=tail", "en"],
    ["locale=f%ZZ", "en"],
    ["bad,name=fr; locale=de", "de"],
  ];
  for (const [cookie, expected] of cases) {
    assert.equal(
      await selectedLocale({
        detection: ["cookie"],
        header: { cookie },
      }),
      expected,
      cookie,
    );
  }

  assert.equal(
    await selectedLocale({
      detection: ["cookie"],
      header: { cookie: "language=fr" },
      localeCookie: "language",
    }),
    "fr",
  );
  assert.equal(
    await selectedLocale({
      detection: ["cookie"],
      header: { cookie: " language =fr" },
      localeCookie: " language ",
    }),
    "en",
  );

  assert.equal(parseCookies("locale=\nfr").has("locale"), false);
  assert.equal(parseCookies(" locale\t=\tfr ").get("locale"), "fr");
  assert.equal(parseCookies("locale=de; locale=fr").get("locale"), "fr");
  assert.equal(parseCookies("locale=fr=tail").get("locale"), "fr=tail");
}

async function sessionAndCallbackConformance() {
  assert.equal(
    await selectedLocale({
      detection: ["session"],
      session: { user: { locale: "fr" } },
    }),
    "fr",
  );
  assert.equal(
    await selectedLocale({
      detection: ["session"],
      session: { user: { preferredLocale: "de" } },
      userLocaleField: "preferredLocale",
    }),
    "de",
  );
  assert.equal(
    await selectedLocale({
      detection: ["session"],
      session: { user: { "profile.locale": "fr" } },
      userLocaleField: "profile.locale",
    }),
    "fr",
  );
  for (const session of [
    undefined,
    {},
    { user: {} },
    { user: { locale: 7 } },
    { user: { locale: "missing" } },
  ]) {
    assert.equal(
      await selectedLocale({ detection: ["session"], session }),
      "en",
    );
  }

  let callbackContext;
  assert.equal(
    await selectedLocale({
      callback: async (ctx) => {
        callbackContext = ctx;
        await Promise.resolve();
        return "fr";
      },
      detection: ["callback"],
    }),
    "fr",
  );
  assert.equal(callbackContext.request, undefined);
  assert.equal(callbackContext.path, "/");
  assert.equal(callbackContext.context.returned.body.code, "PROBE");

  let callbackCalls = 0;
  assert.equal(
    await selectedLocale({
      callback: () => {
        callbackCalls += 1;
        return "de";
      },
      detection: ["header", "callback"],
      header: { "accept-language": "fr" },
    }),
    "fr",
  );
  assert.equal(callbackCalls, 0);

  assert.equal(
    await selectedLocale({
      callback: () => "missing",
      detection: ["callback"],
    }),
    "en",
  );
  assert.equal(
    await selectedLocale({
      callback: () => "fr",
      detection: [],
    }),
    "en",
  );

  const competingHeaders = {
    "accept-language": "fr",
    cookie: "locale=de",
  };
  assert.equal(
    await selectedLocale({
      detection: ["header", "cookie"],
      header: competingHeaders,
    }),
    "fr",
  );
  assert.equal(
    await selectedLocale({
      detection: ["cookie", "header"],
      header: competingHeaders,
    }),
    "de",
  );
}

async function catalogConformance() {
  assert.deepEqual(Object.keys(locales), catalogLocales);
  assert.deepEqual(Object.keys(localeExports), catalogLocales);
  const englishKeys = Object.keys(locales.en).sort();
  assert.equal(englishKeys.length, 34);
  for (const locale of catalogLocales) {
    assert.equal(locales[locale], localeExports[locale]);
    assert.deepEqual(Object.keys(locales[locale]).sort(), englishKeys, locale);
    assert.equal(Object.keys(locales[locale]).length, 34, locale);
    for (const [code, message] of Object.entries(locales[locale])) {
      assert.equal(typeof code, "string");
      assert.equal(typeof message, "string", `${locale}.${code}`);
      assert.notEqual(message.length, 0, `${locale}.${code}`);
    }
  }

  const canonicalCatalog = JSON.stringify(sortedObject(localeExports));
  assert.equal(Buffer.byteLength(canonicalCatalog, "utf8"), catalogBytes);
  assert.equal(
    createHash("sha256").update(canonicalCatalog).digest("hex"),
    catalogDigest,
  );
  const committedCatalog = await readFile(
    new URL("../src/i18n/catalogs.json", import.meta.url),
    "utf8",
  );
  assert.equal(committedCatalog, canonicalCatalog);
}

export async function i18nConformance() {
  exportAndDescriptorConformance();
  await clientConformance();
  await apiErrorConformance();
  await headerConformance();
  await cookieConformance();
  await sessionAndCallbackConformance();
  await catalogConformance();
  console.log("ok - Better Auth i18n plugin contract");
}

export async function i18nNativeConformance(origin) {
  const client = createAuthClient({
    baseURL: origin,
    plugins: [i18nClient()],
  });
  const result = await client.signIn.email(
    {
      email: "missing-i18n-user@example.com",
      password: "wrong password",
    },
    {
      headers: {
        "accept-language": "fr-CA",
        origin,
      },
    },
  );
  assert.equal(result.data, null);
  assert.equal(result.error?.status, 401);
  assert.equal(result.error?.code, "INVALID_EMAIL_OR_PASSWORD");
  assert.equal(result.error?.message, "Email ou mot de passe invalide");
  assert.equal(result.error?.originalMessage, "Invalid email or password");
  console.log("ok - official i18n client against native server");
}
