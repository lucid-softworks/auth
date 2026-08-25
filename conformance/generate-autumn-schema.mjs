import { createHash } from "node:crypto";
import { rmSync } from "node:fs";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.join(here, "node_modules", "autumn-js");
const output = path.join(here, "..", "src", "autumn", "schema", "sdk-0.10.18.json");
const expectedPackageVersion = "1.2.53";
const expectedSdkVersion = "0.10.18";

const operations = [
  ["getOrCreateCustomer", "GetOrCreateCustomerParams$outboundSchema", "Customer$inboundSchema"],
  ["getEntity", "GetEntityParams$outboundSchema", "GetEntityResponse$inboundSchema"],
  ["attach", "AttachParams$outboundSchema", "AttachResponse$inboundSchema"],
  ["previewAttach", "PreviewAttachParams$outboundSchema", "PreviewAttachResponse$inboundSchema"],
  ["updateSubscription", "UpdateSubscriptionParams$outboundSchema", "BillingUpdateResponse$inboundSchema"],
  ["previewUpdateSubscription", "PreviewUpdateParams$outboundSchema", "PreviewUpdateResponse$inboundSchema"],
  ["openCustomerPortal", "OpenCustomerPortalParams$outboundSchema", "OpenCustomerPortalResponse$inboundSchema"],
  ["createReferralCode", "CreateReferralCodeParams$outboundSchema", "CreateReferralCodeResponse$inboundSchema"],
  ["redeemReferralCode", "RedeemReferralCodeParams$outboundSchema", "RedeemReferralCodeResponse$inboundSchema"],
  ["listPlans", "ListPlansParams$outboundSchema", "ListPlansResponse$inboundSchema"],
  ["listEvents", "EventsListParams$outboundSchema", "ListEventsResponse$inboundSchema"],
  ["aggregateEvents", "EventsAggregateParams$outboundSchema", "AggregateEventsResponse$inboundSchema"],
  ["multiAttach", "MultiAttachParams$outboundSchema", "MultiAttachResponse$inboundSchema"],
  ["previewMultiAttach", "PreviewMultiAttachParams$outboundSchema", "PreviewMultiAttachResponse$inboundSchema"],
  ["setupPayment", "SetupPaymentParams$outboundSchema", "SetupPaymentResponse$inboundSchema"],
];

const packageJson = JSON.parse(await readFile(path.join(packageRoot, "package.json"), "utf8"));
if (packageJson.version !== expectedPackageVersion) {
  throw new Error(`expected autumn-js ${expectedPackageVersion}, found ${packageJson.version}`);
}

// Smart-union alternatives are held in generated closures. Instrument a disposable copy so the
// catalog captures them without changing the installed immutable package.
const temporaryRoot = await mkdtemp(path.join(packageRoot, ".lucid-autumn-schema-"));
process.on("exit", () => rmSync(temporaryRoot, { recursive: true, force: true }));
const distRoot = path.join(temporaryRoot, "dist");
await cp(path.join(packageRoot, "dist"), distRoot, { recursive: true });

async function exposeSmartUnions(filename) {
  let source = await readFile(filename, "utf8");
  const start = source.indexOf("function smartUnion(options)");
  const end = source.indexOf("\nfunction better", start);
  if (start < 0 || end < 0) throw new Error(`could not find smartUnion in ${filename}`);
  const segment = source.slice(start, end);
  const opened = segment.replace(/return (z\d+)\.pipe\(/, "return Object.assign($1.pipe(");
  if (opened === segment) throw new Error(`could not open smartUnion instrumentation in ${filename}`);
  const closing = opened.lastIndexOf("  );");
  if (closing < 0) throw new Error(`could not close smartUnion instrumentation in ${filename}`);
  const instrumented = `${opened.slice(0, closing)}  ), { __autumnOptions: options });${opened.slice(closing + 4)}`;
  source = `${source.slice(0, start)}${instrumented}${source.slice(end)}`;
  await writeFile(filename, source);
}

await exposeSmartUnions(path.join(distRoot, "sdk", "index.mjs"));
await exposeSmartUnions(path.join(distRoot, "better-auth", "chunk-AI73OSOF.mjs"));

const sdk = await import(pathToFileURL(path.join(distRoot, "sdk", "index.mjs")));
const { routeConfigs } = await import(
  pathToFileURL(path.join(distRoot, "better-auth", "chunk-IIOL3QPN.mjs"))
);
const { omitProtectedBodyFields } = await import(
  pathToFileURL(path.join(distRoot, "better-auth", "chunk-GJAMWZNZ.mjs"))
);

const roots = [];
for (const [operation, outboundName, inboundName] of operations) {
  const route = routeConfigs.find(candidate => candidate.route === operation);
  if (!route) throw new Error(`missing Better Auth route schema for ${operation}`);
  const outbound = sdk[outboundName];
  const inbound = sdk[inboundName];
  if (!outbound || !inbound) throw new Error(`missing SDK schema for ${operation}`);
  roots.push([`public:${operation}`, omitProtectedBodyFields({ schema: route.bodySchema })]);
  roots.push([`outbound:${operation}`, outbound]);
  roots.push([`inbound:${operation}`, inbound]);
}

const ids = new Map();
const nodes = [];

function nodeId(schema) {
  if (ids.has(schema)) return ids.get(schema);
  const id = nodes.length;
  ids.set(schema, id);
  nodes.push(null);
  nodes[id] = serialize(schema);
  return id;
}

function serialize(schema) {
  const definition = schema?._zod?.def;
  if (!definition) throw new Error("encountered a value without a Zod definition");
  switch (definition.type) {
    case "any":
    case "unknown":
    case "boolean":
    case "null":
    case "undefined":
      return { type: definition.type };
    case "string":
      return { type: "string", format: definition.format ?? null };
    case "number":
      return { type: "number", format: definition.format ?? null };
    case "literal":
      return { type: "literal", values: definition.values };
    case "enum":
      return { type: "literal", values: [...new Set(Object.values(definition.entries))] };
    case "nullable":
    case "optional":
      return { type: definition.type, inner: nodeId(definition.innerType) };
    case "default":
      return { type: "default", inner: nodeId(definition.innerType), value: definition.defaultValue };
    case "array":
      return { type: "array", element: nodeId(definition.element) };
    case "record":
      return { type: "record", key: nodeId(definition.keyType), value: nodeId(definition.valueType) };
    case "union":
      return { type: "union", options: definition.options.map(nodeId) };
    case "intersection":
      return { type: "intersection", left: nodeId(definition.left), right: nodeId(definition.right) };
    case "lazy":
      return { type: "reference", inner: nodeId(definition.getter()) };
    case "object":
      return serializeObject(schema);
    case "pipe":
      return serializePipe(schema);
    default:
      throw new Error(`unsupported Zod node type: ${definition.type}`);
  }
}

function serializeObject(schema, remap = null) {
  const shape = schema._zod.def.shape;
  const outputNames = remap ?? Object.fromEntries(Object.keys(shape).map(name => [name, name]));
  return {
    type: "object",
    fields: Object.entries(shape).map(([input, child]) => ({
      input,
      output: outputNames[input],
      schema: nodeId(child),
    })),
  };
}

function objectRemap(definition) {
  const inbound = definition.in._zod.def;
  const transform = definition.out._zod.def;
  const markers = Object.fromEntries(
    Object.keys(inbound.shape).map((name, index) => [name, `__autumn_schema_field_${index}__`]),
  );
  const transformed = transform.transform(markers);
  const markerToOutput = new Map(Object.entries(transformed).map(([name, marker]) => [marker, name]));
  return Object.fromEntries(
    Object.entries(markers).map(([input, marker]) => {
      const outputName = markerToOutput.get(marker);
      if (!outputName) throw new Error(`transform dropped ${input}`);
      return [input, outputName];
    }),
  );
}

function serializePipe(schema) {
  const definition = schema._zod.def;
  const inbound = definition.in._zod.def;
  const transform = definition.out._zod.def;
  if (transform.type !== "transform") throw new Error("unsupported pipe output");
  if (schema.__autumnOptions) {
    return { type: "smartUnion", options: schema.__autumnOptions.map(nodeId) };
  }
  if (inbound.type === "object") return serializeObject(definition.in, objectRemap(definition));

  const source = transform.transform.toString();
  if (source.includes("JSON.stringify")) return { type: "jsonStringify", inner: nodeId(definition.in) };
  if (source.includes("const num = Number(x)")) return { type: "coerceNumber", inner: nodeId(definition.in) };
  if (source.includes('lower === "true"')) return { type: "coerceBoolean", inner: nodeId(definition.in) };
  if (source.includes("defaultToZeroValue")) {
    const issues = [];
    const value = transform.transform(undefined, { issues });
    if (issues.length > 0 || value === undefined) throw new Error("could not recover zero default");
    return { type: "zeroDefault", value };
  }
  if (inbound.type === "null" && source.includes("unrecognized(void 0)")) {
    return { type: "toUndefined", inner: nodeId(definition.in) };
  }
  if (source.includes("unrecognized")) return { type: "unrecognized", inner: nodeId(definition.in) };
  throw new Error(`unsupported transformed ${inbound.type}: ${source.slice(0, 160)}`);
}

const rootIds = Object.fromEntries(roots.map(([name, schema]) => [name, nodeId(schema)]));
const catalog = {
  generatedFrom: `autumn-js@${expectedPackageVersion} (@useautumn/sdk@${expectedSdkVersion})`,
  roots: rootIds,
  nodes,
};
const content = `${JSON.stringify(catalog)}\n`;
const digest = createHash("sha256").update(content).digest("hex");
const check = process.argv.includes("--check");
if (check) {
  const current = await readFile(output, "utf8");
  if (current !== content) {
    throw new Error("Autumn SDK schema catalog is stale; run `npm run generate:autumn-schema`");
  }
} else {
  await mkdir(path.dirname(output), { recursive: true });
  await writeFile(output, content);
}
await rm(temporaryRoot, { recursive: true, force: true });
console.log(`${check ? "verified" : "wrote"} ${path.relative(process.cwd(), output)} (${nodes.length} nodes, sha256 ${digest})`);
