import compatibility from "../../COMPATIBILITY.md?raw";
import readme from "../../README.md?raw";
import databaseIdMigration from "../../docs/database-id-migration.md?raw";
import frameworks from "../../docs/frameworks.md?raw";
import installation from "../../docs/installation.md?raw";
import mssql from "../../docs/mssql.md?raw";
import production from "../../docs/production.md?raw";

export type Doc = {
  path: string;
  title: string;
  description: string;
  source: string;
  content: string;
  group: "Overview" | "Guides" | "Reference";
};

export const docs: Doc[] = [
  {
    path: "/",
    title: "Introduction",
    description: "Native Rust authentication with the Better Auth protocol.",
    source: "README.md",
    content: readme,
    group: "Overview",
  },
  {
    path: "/installation",
    title: "Installation",
    description: "Install lucid-auth and connect your storage adapter.",
    source: "docs/installation.md",
    content: installation,
    group: "Guides",
  },
  {
    path: "/frameworks",
    title: "Clients & frameworks",
    description: "Connect Better Auth clients across browser, SSR, mobile, and Electron.",
    source: "docs/frameworks.md",
    content: frameworks,
    group: "Guides",
  },
  {
    path: "/production",
    title: "Production",
    description: "Security, proxy, database, and deployment checklist.",
    source: "docs/production.md",
    content: production,
    group: "Guides",
  },
  {
    path: "/database-id-migration",
    title: "Database ID migration",
    description: "Choose and safely migrate database ID strategies.",
    source: "docs/database-id-migration.md",
    content: databaseIdMigration,
    group: "Guides",
  },
  {
    path: "/mssql",
    title: "Microsoft SQL Server",
    description: "Configure, migrate, and secure the native MSSQL adapter.",
    source: "docs/mssql.md",
    content: mssql,
    group: "Reference",
  },
  {
    path: "/compatibility",
    title: "Compatibility",
    description: "Method-level Better Auth 1.7.2 compatibility and known boundaries.",
    source: "COMPATIBILITY.md",
    content: compatibility,
    group: "Reference",
  },
];

export const docsByPath = new Map(docs.map((doc) => [doc.path, doc]));
export const docsBySource = new Map(docs.map((doc) => [doc.source, doc]));
