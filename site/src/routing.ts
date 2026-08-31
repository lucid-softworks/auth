import { docsBySource, type Doc } from "./content";

export type Location = {
  path: string;
  anchor: string;
};

const REPOSITORY = "https://github.com/lucid-softworks/auth";

export function readLocation(): Location {
  const value = window.location.hash.slice(1) || "/";
  const separator = value.indexOf("#");
  const rawPath = separator === -1 ? value : value.slice(0, separator);
  return {
    path: rawPath.startsWith("/") ? rawPath : `/${rawPath}`,
    anchor: separator === -1 ? "" : decodeURIComponent(value.slice(separator + 1)),
  };
}

export function docHref(path: string, anchor = ""): string {
  return `#${path}${anchor ? `#${anchor}` : ""}`;
}

function normalizedSource(source: string, href: string): string {
  const sourceParts = source.split("/");
  sourceParts.pop();
  for (const part of href.split("/")) {
    if (part === "..") sourceParts.pop();
    else if (part !== "." && part !== "") sourceParts.push(part);
  }
  return sourceParts.join("/");
}

export function resolveMarkdownHref(current: Doc, href?: string): string | undefined {
  if (!href) return href;
  if (/^(?:https?:|mailto:)/.test(href)) return href;
  if (href.startsWith("#")) return docHref(current.path, href.slice(1));

  const [relativePath, anchor = ""] = href.split("#", 2);
  const source = normalizedSource(current.source, relativePath);
  const linkedDoc = docsBySource.get(source);
  if (linkedDoc) return docHref(linkedDoc.path, anchor);

  return `${REPOSITORY}/blob/main/${source}${anchor ? `#${anchor}` : ""}`;
}

export function sourceUrl(doc: Doc): string {
  return `${REPOSITORY}/blob/main/${doc.source}`;
}

export function editUrl(doc: Doc): string {
  return `${REPOSITORY}/edit/main/${doc.source}`;
}
