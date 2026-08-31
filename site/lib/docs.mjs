function baseSlug(value) {
  return value
    .toLowerCase()
    .replace(/<[^>]*>/g, "")
    .replace(/[`*_~]/g, "")
    .replace(/[^\p{Letter}\p{Number}\s-]/gu, "")
    .trim()
    .replace(/\s+/g, "-");
}

function headingTitle(value) {
  return value.replace(/\[([^\]]+)]\([^)]*\)/g, "$1").trim();
}

export function extractMarkdownHeadings(markdown) {
  const headings = [];
  const seen = new Map();
  let fenced = false;

  for (const [line, value] of markdown.split("\n").entries()) {
    if (/^\s*(```|~~~)/.test(value)) {
      fenced = !fenced;
      continue;
    }
    if (fenced) continue;

    const match = /^(#{1,6})\s+(.+?)\s*#*$/.exec(value);
    if (!match) continue;
    const title = headingTitle(match[2]);
    const base = baseSlug(title);
    const duplicate = seen.get(base) ?? 0;
    seen.set(base, duplicate + 1);
    headings.push({
      depth: match[1].length,
      line,
      title,
      slug: duplicate === 0 ? base : `${base}-${duplicate}`,
    });
  }

  return headings;
}

function pagePath(sectionPath, heading, parents) {
  const parent = parents.get(heading.depth - 1);
  const base = parent?.path ?? sectionPath;
  return `${base === "/" ? "" : base}/${heading.slug}`;
}

function description(markdown, fallback) {
  const prose = markdown
    .replace(/```[\s\S]*?```/g, " ")
    .split(/\n\s*\n/)
    .find((block) => {
      const lines = block.split("\n").map((line) => line.trim()).filter(Boolean);
      return lines.length > 0 && lines.some((line) =>
        !/^(?:[#>|-]|\d+\.|<|\[!)/.test(line),
      );
    });
  if (!prose) return fallback;
  const text = prose
    .replace(/^\s*(?:[#>|-]|\d+\.)\s*/gm, "")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/!?\[([^\]]*)]\([^)]*\)/g, "$1")
    .replace(/[*_~]/g, "")
    .replace(/\s+/g, " ")
    .trim();
  if (!text) return fallback;
  return text.length > 180 ? `${text.slice(0, 177).trimEnd()}…` : text;
}

export function splitDocument(config, markdown) {
  const lines = markdown.split("\n");
  const headings = extractMarkdownHeadings(markdown);
  const rootHeading = headings.find((heading) => heading.depth === 1);
  const splitHeadings = headings.filter(
    (heading) => heading.depth >= 2 && heading.depth <= config.splitDepth,
  );
  const firstSectionLine = splitHeadings[0]?.line ?? lines.length;
  const introStart = rootHeading?.line === 0 ? 1 : 0;
  const pages = [
    {
      path: config.path,
      title: config.title,
      description: config.description,
      source: config.source,
      sourceAnchor: "",
      sourceRootPath: config.path,
      parentPath: null,
      depth: 1,
      group: config.group,
      content: lines.slice(introStart, firstSectionLine).join("\n").trim(),
      anchors: {},
    },
  ];
  const parents = new Map();

  for (const [index, heading] of splitHeadings.entries()) {
    for (const depth of [...parents.keys()]) {
      if (depth >= heading.depth) parents.delete(depth);
    }
    const path = pagePath(config.sectionPath, heading, parents);
    const parentPath = parents.get(heading.depth - 1)?.path ?? config.path;
    const end = splitHeadings[index + 1]?.line ?? lines.length;
    const content = lines.slice(heading.line + 1, end).join("\n").trim();
    const page = {
      path,
      title: heading.title,
      description: description(content, config.description),
      source: config.source,
      sourceAnchor: heading.slug,
      sourceRootPath: config.path,
      parentPath,
      depth: heading.depth,
      group: config.group,
      content,
      anchors: { [heading.slug]: "" },
    };
    pages.push(page);
    parents.set(heading.depth, page);
  }

  for (const page of pages) {
    const local = extractMarkdownHeadings(page.content);
    const sourceStart = page.sourceAnchor
      ? headings.find((heading) => heading.slug === page.sourceAnchor)?.line ?? 0
      : 0;
    const sourceHeadings = headings.filter((heading) => {
      if (heading.line <= sourceStart) return false;
      const nextPage = pages.find(
        (candidate) => candidate.sourceAnchor && candidate.path !== page.path &&
          (headings.find((item) => item.slug === candidate.sourceAnchor)?.line ?? Infinity) > sourceStart,
      );
      const end = nextPage
        ? headings.find((item) => item.slug === nextPage.sourceAnchor)?.line ?? Infinity
        : Infinity;
      return heading.line < end;
    });
    for (const [index, heading] of sourceHeadings.entries()) {
      if (local[index]) page.anchors[heading.slug] = local[index].slug;
    }
  }

  return pages;
}
