export type Heading = {
  depth: number;
  title: string;
  slug: string;
};

function baseSlug(value: string): string {
  return value
    .toLowerCase()
    .replace(/<[^>]*>/g, "")
    .replace(/[`*_~]/g, "")
    .replace(/[^\p{Letter}\p{Number}\s-]/gu, "")
    .trim()
    .replace(/\s+/g, "-");
}

export function extractHeadings(markdown: string): Heading[] {
  const headings: Heading[] = [];
  const seen = new Map<string, number>();
  let fenced = false;

  for (const line of markdown.split("\n")) {
    if (/^\s*(```|~~~)/.test(line)) {
      fenced = !fenced;
      continue;
    }
    if (fenced) continue;

    const match = /^(#{1,3})\s+(.+?)\s*#*$/.exec(line);
    if (!match) continue;

    const title = match[2].replace(/\[([^\]]+)]\([^)]*\)/g, "$1").trim();
    const base = baseSlug(title);
    const duplicate = seen.get(base) ?? 0;
    seen.set(base, duplicate + 1);
    headings.push({
      depth: match[1].length,
      title,
      slug: duplicate === 0 ? base : `${base}-${duplicate}`,
    });
  }

  return headings;
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
