import { extractMarkdownHeadings } from "../lib/docs.mjs";

export type Heading = {
  depth: number;
  title: string;
  slug: string;
};

export function extractHeadings(markdown: string): Heading[] {
  return extractMarkdownHeadings(markdown).map(({ depth, title, slug }) => ({
    depth,
    title,
    slug,
  }));
}

export function plainText(markdown: string): string {
  return markdown
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/!?(?:\[([^\]]*)])\([^)]*\)/g, "$1")
    .replace(/[#>*_|~-]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}
