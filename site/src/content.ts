import compatibility from "../../COMPATIBILITY.md?raw";
import readme from "../../README.md?raw";
import databaseIdMigration from "../../docs/database-id-migration.md?raw";
import frameworks from "../../docs/frameworks.md?raw";
import installation from "../../docs/installation.md?raw";
import mssql from "../../docs/mssql.md?raw";
import production from "../../docs/production.md?raw";
import configsJson from "../content.config.json";
import { splitDocument, type DocumentConfig, type DocumentPage } from "../lib/docs.mjs";

export type Doc = DocumentPage;

const markdownBySource: Record<string, string> = {
  "README.md": readme,
  "COMPATIBILITY.md": compatibility,
  "docs/database-id-migration.md": databaseIdMigration,
  "docs/frameworks.md": frameworks,
  "docs/installation.md": installation,
  "docs/mssql.md": mssql,
  "docs/production.md": production,
};

export const sourceConfigs = configsJson as DocumentConfig[];
export const docs = sourceConfigs.flatMap((config) =>
  splitDocument(config, markdownBySource[config.source]),
);

export const docsByPath = new Map(docs.map((doc) => [doc.path, doc]));
export const sourceRoots = docs.filter((doc) => doc.depth === 1);

const anchorTargets = new Map<string, { path: string; anchor: string }>();
for (const doc of docs) {
  for (const [sourceAnchor, localAnchor] of Object.entries(doc.anchors)) {
    anchorTargets.set(`${doc.source}#${sourceAnchor}`, {
      path: doc.path,
      anchor: localAnchor,
    });
  }
}

export function findAnchorTarget(source: string, anchor: string) {
  return anchorTargets.get(`${source}#${anchor}`);
}

export function sourceRoot(source: string) {
  return sourceRoots.find((doc) => doc.source === source);
}
