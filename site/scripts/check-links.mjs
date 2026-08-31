import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, normalize, resolve } from "node:path";
import { extractMarkdownHeadings, splitDocument } from "../lib/docs.mjs";

const root = resolve(import.meta.dirname, "../..");
const configs = JSON.parse(readFileSync(join(root, "site/content.config.json"), "utf8"));
const sources = configs.map((config) => config.source);

function markdownFiles(directory, prefix = "") {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    const name = join(prefix, entry.name);
    if (entry.isDirectory()) return markdownFiles(path, name);
    return entry.isFile() && entry.name.endsWith(".md") ? [name] : [];
  });
}

const expectedSources = ["README.md", "COMPATIBILITY.md", ...markdownFiles(join(root, "docs"), "docs")].sort();
const migratedSources = [...sources].sort();
if (expectedSources.join("\n") !== migratedSources.join("\n")) {
  throw new Error(`Site content inventory is stale.\nExpected:\n${expectedSources.join("\n")}\nConfigured:\n${migratedSources.join("\n")}`);
}

function slug(value) {
  return value
    .toLowerCase()
    .replace(/<[^>]*>/g, "")
    .replace(/[`*_~]/g, "")
    .replace(/[^\p{Letter}\p{Number}\s-]/gu, "")
    .trim()
    .replace(/\s+/g, "-");
}

function anchors(markdown) {
  const result = new Set();
  const seen = new Map();
  let fenced = false;
  for (const line of markdown.split("\n")) {
    if (/^\s*(```|~~~)/.test(line)) {
      fenced = !fenced;
      continue;
    }
    if (fenced) continue;
    const heading = /^#{1,6}\s+(.+?)\s*#*$/.exec(line);
    if (!heading) continue;
    const base = slug(heading[1].replace(/\[([^\]]+)]\([^)]*\)/g, "$1"));
    const count = seen.get(base) ?? 0;
    seen.set(base, count + 1);
    result.add(count === 0 ? base : `${base}-${count}`);
  }
  return result;
}

const content = new Map(sources.map((source) => [source, readFileSync(join(root, source), "utf8")]));
const anchorMap = new Map([...content].map(([source, markdown]) => [source, anchors(markdown)]));
const errors = [];
const pages = configs.flatMap((config) => splitDocument(config, content.get(config.source)));
const pagePaths = new Set();

for (const page of pages) {
  if (pagePaths.has(page.path)) errors.push(`duplicate documentation route ${page.path}`);
  pagePaths.add(page.path);
  const localAnchors = new Set(extractMarkdownHeadings(page.content).map((heading) => heading.slug));
  for (const [sourceAnchor, localAnchor] of Object.entries(page.anchors)) {
    if (localAnchor && !localAnchors.has(localAnchor)) {
      errors.push(`${page.path}: missing rendered #${localAnchor} for source #${sourceAnchor}`);
    }
  }
}

for (const [source, markdown] of content) {
  const sourcePages = pages.filter((page) => page.source === source);
  for (const heading of extractMarkdownHeadings(markdown).filter((item) => item.depth > 1)) {
    const owners = sourcePages.filter((page) => Object.hasOwn(page.anchors, heading.slug));
    if (owners.length !== 1) errors.push(`${source}: #${heading.slug} has ${owners.length} route owners`);
  }
}

for (const [source, markdown] of content) {
  let fenced = false;
  for (const [index, line] of markdown.split("\n").entries()) {
    if (/^\s*(```|~~~)/.test(line)) {
      fenced = !fenced;
      continue;
    }
    if (fenced) continue;
    for (const match of line.matchAll(/!?\[[^\]]*]\(([^)\s]+)(?:\s+"[^"]*")?\)/g)) {
      const href = match[1].replace(/^<|>$/g, "");
      if (/^(?:https?:|mailto:)/.test(href)) continue;
      const [pathPart, rawAnchor = ""] = href.split("#", 2);
      const target = pathPart ? normalize(join(dirname(source), decodeURIComponent(pathPart))) : source;
      if (!existsSync(join(root, target))) {
        errors.push(`${source}:${index + 1}: missing ${target}`);
        continue;
      }
      if (rawAnchor && target.endsWith(".md") && !anchorMap.get(target)?.has(decodeURIComponent(rawAnchor).toLowerCase())) {
        errors.push(`${source}:${index + 1}: missing #${rawAnchor} in ${target}`);
      }
    }
  }
}

if (errors.length) throw new Error(`Broken documentation links:\n${errors.join("\n")}`);
console.log(`Checked ${sources.length} Markdown sources, ${pages.length} routes, and their local links.`);
