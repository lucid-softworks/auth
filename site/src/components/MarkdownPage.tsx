import { ChevronLeft, ChevronRight, ExternalLink, FilePenLine } from "lucide-react";
import type { ReactNode } from "react";
import ReactMarkdown, { type Components } from "react-markdown";
import rehypeAutolinkHeadings from "rehype-autolink-headings";
import rehypeHighlight from "rehype-highlight";
import rehypeSlug from "rehype-slug";
import remarkGfm from "remark-gfm";
import { docs, type Doc } from "../content";
import type { Heading } from "../markdown";
import { editUrl, resolveMarkdownHref, sourceUrl } from "../routing";
import { DocLink } from "./DocLink";

type MarkdownPageProps = {
  doc: Doc;
  headings: Heading[];
  activeAnchor: string;
};

function Table({ children }: { children?: ReactNode }) {
  return (
    <div className="table-frame">
      <div className="table-scroll" role="region" aria-label="Scrollable table" tabIndex={0}><table>{children}</table></div>
      <span className="table-scroll-hint" aria-hidden="true">Swipe to see every column →</span>
    </div>
  );
}

export function MarkdownPage({ doc, headings, activeAnchor }: MarkdownPageProps) {
  const currentIndex = docs.findIndex((candidate) => candidate.path === doc.path);
  const previous = docs[currentIndex - 1];
  const next = docs[currentIndex + 1];
  const components: Components = {
    a({ href, children, node: _node, ...props }) {
      const resolved = resolveMarkdownHref(doc, href);
      if (!resolved) return <span>{children}</span>;
      if (!resolved.external) {
        return <DocLink path={resolved.path} anchor={resolved.anchor} className={props.className}>{children}</DocLink>;
      }
      return <a href={resolved.href} target="_blank" rel="noreferrer" {...props}>{children}<ExternalLink className="inline-external" size={12} /></a>;
    },
    table: Table,
  };

  return (
    <div className={`page-grid ${headings.length ? "" : "without-toc"}`}>
      <main className="content-column" id="main-content">
        <div className="page-kicker">{doc.group}</div>
        <h1 className="page-title">{doc.title}</h1>
        <p className="page-summary">{doc.description}</p>
        <div className="source-actions">
          <a href={sourceUrl(doc)} target="_blank" rel="noreferrer"><ExternalLink size={14} /> View source</a>
          <a href={editUrl(doc)} target="_blank" rel="noreferrer"><FilePenLine size={14} /> Edit this page</a>
        </div>
        <article className="markdown-body">
          <ReactMarkdown
            remarkPlugins={[remarkGfm]}
            rehypePlugins={[rehypeSlug, [rehypeAutolinkHeadings, { behavior: "wrap" }], rehypeHighlight]}
            components={components}
          >
            {doc.content}
          </ReactMarkdown>
        </article>
        <nav className="page-pagination" aria-label="Adjacent documentation pages">
          {previous ? <DocLink path={previous.path}><small><ChevronLeft size={13} /> Previous</small><strong>{previous.title}</strong></DocLink> : <span />}
          {next && <DocLink className="next" path={next.path}><small>Next <ChevronRight size={13} /></small><strong>{next.title}</strong></DocLink>}
        </nav>
        <footer className="content-footer">
          <span>lucid-auth</span> · Better Auth protocol, native Rust execution.
        </footer>
      </main>
      {headings.length > 0 && <aside className="toc" aria-label="On this page">
        <h2>On this page</h2>
        <nav>
          {headings.map((heading) => (
            <DocLink
              className={`${heading.depth > doc.depth + 1 ? "toc-nested" : ""} ${activeAnchor === heading.slug ? "active" : ""}`}
              path={doc.path}
              anchor={heading.slug}
              key={heading.slug}
            >
              {heading.title}
            </DocLink>
          ))}
        </nav>
      </aside>}
    </div>
  );
}
