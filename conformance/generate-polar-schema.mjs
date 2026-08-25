import { createHash } from "node:crypto";
import { rmSync } from "node:fs";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const sdkRoot = path.join(here, "node_modules", "@polar-sh", "sdk");
const output = path.join(here, "..", "src", "polar", "schema", "sdk-0.47.1.json");
const expectedVersion = "0.47.1";

const componentRoots = [
  ["checkout", "checkout.js", "Checkout$inboundSchema"],
  ["customer", "customer.js", "Customer$inboundSchema"],
  ["customerSession", "customersession.js", "CustomerSession$inboundSchema"],
  ["customerState", "customerstate.js", "CustomerState$inboundSchema"],
  ["customerPage", "listresourcecustomer.js", "ListResourceCustomer$inboundSchema"],
  [
    "benefitGrantPage",
    "listresourcecustomerbenefitgrant.js",
    "ListResourceCustomerBenefitGrant$inboundSchema",
  ],
  [
    "customerSubscriptionPage",
    "listresourcecustomersubscription.js",
    "ListResourceCustomerSubscription$inboundSchema",
  ],
  ["orderPage", "listresourcecustomerorder.js", "ListResourceCustomerOrder$inboundSchema"],
  [
    "meterPage",
    "listresourcecustomercustomermeter.js",
    "ListResourceCustomerCustomerMeter$inboundSchema",
  ],
  ["subscriptionPage", "listresourcesubscription.js", "ListResourceSubscription$inboundSchema"],
  ["ingestion", "eventsingestresponse.js", "EventsIngestResponse$inboundSchema"],
];

const outboundRoots = [
  ["checkoutCreate", "components", "checkoutcreate.js", "CheckoutCreate$outboundSchema"],
  ["customerCreate", "components", "customercreate.js", "CustomerCreate$outboundSchema"],
  ["customerUpdate", "components", "customerupdate.js", "CustomerUpdate$outboundSchema"],
  ["customerUpdateExternal", "components", "customerupdateexternalid.js", "CustomerUpdateExternalID$outboundSchema"],
  ["eventsIngest", "components", "eventsingest.js", "EventsIngest$outboundSchema"],
  ["customerSessionCreate", "operations", "customersessionscreate.js", "CustomerSessionsCreateCustomerSessionCreate$outboundSchema"],
  ["customersList", "operations", "customerslist.js", "CustomersListRequest$outboundSchema"],
  ["benefitGrantsList", "operations", "customerportalbenefitgrantslist.js", "CustomerPortalBenefitGrantsListRequest$outboundSchema"],
  ["customerSubscriptionsList", "operations", "customerportalsubscriptionslist.js", "CustomerPortalSubscriptionsListRequest$outboundSchema"],
  ["customerOrdersList", "operations", "customerportalorderslist.js", "CustomerPortalOrdersListRequest$outboundSchema"],
  ["customerMetersList", "operations", "customerportalcustomermeterslist.js", "CustomerPortalCustomerMetersListRequest$outboundSchema"],
  ["subscriptionsList", "operations", "subscriptionslist.js", "SubscriptionsListRequest$outboundSchema"],
];

const packageJson = JSON.parse(await readFile(path.join(sdkRoot, "package.json"), "utf8"));
if (packageJson.version !== expectedVersion) {
  throw new Error(`expected @polar-sh/sdk ${expectedVersion}, found ${packageJson.version}`);
}

// Generated SDK schemas hide smart-union candidates in a closure. Instrument a disposable
// copy so the checked-in catalog records those candidates without modifying node_modules.
const temporaryRoot = await mkdtemp(path.join(sdkRoot, ".lucid-schema-"));
process.on("exit", () => rmSync(temporaryRoot, { recursive: true, force: true }));
const esmRoot = path.join(temporaryRoot, "esm");
await cp(path.join(sdkRoot, "dist", "esm"), esmRoot, { recursive: true });
const smartUnionPath = path.join(esmRoot, "types", "smartUnion.js");
let smartUnionSource = await readFile(smartUnionPath, "utf8");
smartUnionSource = smartUnionSource
  .replace("    return z.pipe(z.unknown(),", "    return Object.assign(z.pipe(z.unknown(),")
  .replace("    }));\n}\nfunction better", "    })), { __polarOptions: options });\n}\nfunction better");
if (!smartUnionSource.includes("__polarOptions")) throw new Error("failed to instrument smartUnion");
await writeFile(smartUnionPath, smartUnionSource);
const components = path.join(esmRoot, "models", "components");
const operations = path.join(esmRoot, "models", "operations");

const roots = [];
for (const [name, filename, exportName] of componentRoots) {
  const module = await import(pathToFileURL(path.join(components, filename)));
  if (!module[exportName]) throw new Error(`missing ${exportName} from ${filename}`);
  roots.push([name, module[exportName], false]);
}

for (const [name, directory, filename, exportName] of outboundRoots) {
  const directoryPath = directory === "components" ? components : operations;
  const module = await import(pathToFileURL(path.join(directoryPath, filename)));
  if (!module[exportName]) throw new Error(`missing ${exportName} from ${filename}`);
  roots.push([`outbound:${name}`, module[exportName], true]);
}

for (const filename of (await readdir(components)).filter(file => /^webhook.*payload\.js$/.test(file)).sort()) {
  const module = await import(pathToFileURL(path.join(components, filename)));
  const entry = Object.entries(module).find(([name]) => name.endsWith("$inboundSchema"));
  if (!entry) continue;
  const schema = entry[1];
  const object = unwrapObject(schema);
  const eventType = object._zod.def.shape.type._zod.def.values[0];
  roots.push([`webhook:${eventType}`, schema, false]);
}

const ids = new Map();
const wireIds = new Map();
const nodes = [];

function nodeId(schema) {
  if (ids.has(schema)) return ids.get(schema);
  const id = nodes.length;
  ids.set(schema, id);
  nodes.push(null);
  nodes[id] = serialize(schema);
  return id;
}

function wireNodeId(schema) {
  if (wireIds.has(schema)) return wireIds.get(schema);
  const id = nodes.length;
  wireIds.set(schema, id);
  nodes.push(null);
  nodes[id] = serializeWire(schema);
  return id;
}

function serialize(schema) {
  const definition = schema?._zod?.def;
  if (!definition) throw new Error("encountered a value without a Zod definition");
  switch (definition.type) {
    case "any":
    case "unknown":
    case "boolean":
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
      return {
        type: "default",
        inner: nodeId(definition.innerType),
        value: definition.defaultValue,
      };
    case "array":
      return { type: "array", element: nodeId(definition.element) };
    case "record":
      return {
        type: "record",
        key: nodeId(definition.keyType),
        value: nodeId(definition.valueType),
      };
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

function serializeWire(schema) {
  const definition = schema?._zod?.def;
  if (!definition) throw new Error("encountered a value without a Zod definition");
  switch (definition.type) {
    case "any":
    case "unknown":
    case "boolean":
      return { type: definition.type };
    case "string":
      return { type: "string", format: definition.format ?? null };
    case "number":
      return { type: "number", format: definition.format ?? null };
    case "date":
      return { type: "date" };
    case "literal":
      return { type: "literal", values: definition.values };
    case "enum":
      return { type: "literal", values: [...new Set(Object.values(definition.entries))] };
    case "nullable":
    case "optional":
      return { type: definition.type, inner: wireNodeId(definition.innerType) };
    case "default":
      return { type: "default", inner: wireNodeId(definition.innerType), value: definition.defaultValue };
    case "array":
      return { type: "array", element: wireNodeId(definition.element) };
    case "record":
      return { type: "record", key: wireNodeId(definition.keyType), value: wireNodeId(definition.valueType) };
    case "union":
      return { type: "union", options: definition.options.map(wireNodeId) };
    case "intersection":
      return { type: "intersection", left: wireNodeId(definition.left), right: wireNodeId(definition.right) };
    case "lazy":
      return { type: "reference", inner: wireNodeId(definition.getter()) };
    case "object":
      return serializeWireObject(schema);
    case "pipe":
      return serializeWirePipe(schema);
    default:
      throw new Error(`unsupported outbound Zod node type: ${definition.type}`);
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

function serializeWireObject(schema, remap = null) {
  const shape = schema._zod.def.shape;
  const outputNames = remap ?? Object.fromEntries(Object.keys(shape).map(name => [name, name]));
  return {
    type: "object",
    fields: Object.entries(shape).map(([input, child]) => ({
      input: outputNames[input],
      output: outputNames[input],
      schema: wireNodeId(child),
    })),
  };
}

function objectRemap(definition) {
  const inbound = definition.in._zod.def;
  const transform = definition.out._zod.def;
  const markers = Object.fromEntries(
    Object.keys(inbound.shape).map((name, index) => [name, `__polar_schema_field_${index}__`]),
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
  if (schema.__polarOptions) {
    return { type: "smartUnion", options: schema.__polarOptions.map(nodeId) };
  }
  if (inbound.type === "string" && inbound.format === "datetime") return { type: "date" };
  if (transform.transform.toString().includes("unrecognized")) {
    return { type: "unrecognized", inner: nodeId(definition.in) };
  }
  if (inbound.type !== "object") throw new Error(`unsupported transformed ${inbound.type}`);

  return serializeObject(definition.in, objectRemap(definition));
}

function serializeWirePipe(schema) {
  const definition = schema._zod.def;
  const inbound = definition.in._zod.def;
  const transform = definition.out._zod.def;
  if (transform.type !== "transform") throw new Error("unsupported outbound pipe output");
  if (schema.__polarOptions) {
    return { type: "smartUnion", options: schema.__polarOptions.map(wireNodeId) };
  }
  if (inbound.type === "date") return { type: "date" };
  if (transform.transform.toString().includes("unrecognized")) {
    return { type: "unrecognized", inner: wireNodeId(definition.in) };
  }
  if (inbound.type !== "object") throw new Error(`unsupported outbound transformed ${inbound.type}`);
  return serializeWireObject(definition.in, objectRemap(definition));
}

function unwrapObject(schema) {
  return schema._zod.def.type === "pipe" ? schema._zod.def.in : schema;
}

const rootIds = Object.fromEntries(
  roots.map(([name, schema, wire]) => [name, wire ? wireNodeId(schema) : nodeId(schema)]),
);
const catalog = {
  generatedFrom: `@polar-sh/sdk@${expectedVersion}`,
  roots: rootIds,
  nodes,
};
const content = `${JSON.stringify(catalog)}\n`;
const digest = createHash("sha256").update(content).digest("hex");
const check = process.argv.includes("--check");
if (check) {
  const current = await readFile(output, "utf8");
  if (current !== content) {
    await rm(temporaryRoot, { recursive: true, force: true });
    throw new Error("Polar SDK schema catalog is stale; run `npm run generate:polar-schema`");
  }
} else {
  await mkdir(path.dirname(output), { recursive: true });
  await writeFile(output, content);
}
await rm(temporaryRoot, { recursive: true, force: true });
console.log(`${check ? "verified" : "wrote"} ${path.relative(process.cwd(), output)} (${nodes.length} nodes, sha256 ${digest})`);
