export type DocumentConfig = {
  source: string;
  path: string;
  sectionPath: string;
  title: string;
  description: string;
  group: "Overview" | "Guides" | "Reference";
  splitDepth: number;
};

export type MarkdownHeading = {
  depth: number;
  line: number;
  title: string;
  slug: string;
};

export type DocumentPage = {
  path: string;
  title: string;
  description: string;
  source: string;
  sourceAnchor: string;
  sourceRootPath: string;
  parentPath: string | null;
  depth: number;
  group: DocumentConfig["group"];
  content: string;
  anchors: Record<string, string>;
};

export function extractMarkdownHeadings(markdown: string): MarkdownHeading[];
export function splitDocument(config: DocumentConfig, markdown: string): DocumentPage[];
