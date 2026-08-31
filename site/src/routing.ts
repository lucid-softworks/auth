import { findAnchorTarget, sourceRoot, type Doc } from "./content";

export type DocLocation = {
  path: string;
  anchor: string;
};

export type ResolvedMarkdownLink =
  | { external: true; href: string }
  | { external: false; path: string; anchor: string };

const REPOSITORY = "https://github.com/lucid-softworks/auth";
const legacySources = new Map([
  ["/", "README.md"],
  ["/installation", "docs/installation.md"],
  ["/frameworks", "docs/frameworks.md"],
  ["/production", "docs/production.md"],
  ["/database-id-migration", "docs/database-id-migration.md"],
  ["/mssql", "docs/mssql.md"],
  ["/compatibility", "COMPATIBILITY.md"],
]);

function normalizedSource(source: string, href: string): string {
  const sourceParts = source.split("/");
  sourceParts.pop();
  for (const part of href.split("/")) {
    if (part === "..") sourceParts.pop();
    else if (part !== "." && part !== "") sourceParts.push(part);
  }
  return sourceParts.join("/");
}

function sourceLocation(source: string, anchor = ""): DocLocation | undefined {
  if (anchor) {
    const target = findAnchorTarget(source, decodeURIComponent(anchor).toLowerCase());
    if (target) return target;
  }
  const root = sourceRoot(source);
  if (root) return { path: root.path, anchor: "" };
}

export function normalizeDocPath(path: string): string {
  if (!path || path === "/") return "/";
  return `/${path.replace(/^\/+|\/+$/g, "")}`;
}

export function resolveMarkdownHref(current: Doc, href?: string): ResolvedMarkdownLink | undefined {
  if (!href) return undefined;
  if (/^(?:https?:|mailto:)/.test(href)) return { external: true, href };
  if (href.startsWith("#")) {
    const target = sourceLocation(current.source, href.slice(1));
    return target ? { external: false, ...target } : undefined;
  }

  const [relativePath, anchor = ""] = href.split("#", 2);
  const source = normalizedSource(current.source, relativePath);
  const target = sourceLocation(source, anchor);
  if (target) return { external: false, ...target };

  return {
    external: true,
    href: `${REPOSITORY}/blob/main/${source}${anchor ? `#${anchor}` : ""}`,
  };
}

export function legacyLocation(hash: string): DocLocation | undefined {
  if (!hash.startsWith("#/")) return undefined;
  const value = hash.slice(1);
  const separator = value.indexOf("#");
  const path = normalizeDocPath(separator === -1 ? value : value.slice(0, separator));
  const anchor = separator === -1 ? "" : value.slice(separator + 1);
  const source = legacySources.get(path);
  return source ? sourceLocation(source, anchor) : undefined;
}

export function legacyPathLocation(path: string, anchor = ""): DocLocation | undefined {
  const source = legacySources.get(normalizeDocPath(path));
  return source ? sourceLocation(source, anchor) : undefined;
}

export function sourceUrl(doc: Doc): string {
  return `${REPOSITORY}/blob/main/${doc.source}${doc.sourceAnchor ? `#${doc.sourceAnchor}` : ""}`;
}

export function editUrl(doc: Doc): string {
  return `${REPOSITORY}/edit/main/${doc.source}${doc.sourceAnchor ? `#${doc.sourceAnchor}` : ""}`;
}
