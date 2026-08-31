import { ChevronLeft, ChevronRight, ExternalLink, FilePenLine } from "lucide-react";
import type { ReactNode } from "react";
import ReactMarkdown, { type Components } from "react-markdown";
import rehypeAutolinkHeadings from "rehype-autolink-headings";
import rehypeHighlight from "rehype-highlight";
import rehypeSlug from "rehype-slug";
import remarkGfm from "remark-gfm";
import { docs, type Doc } from "../content";
import type { Heading } from "../markdown";
import { docHref, editUrl, resolveMarkdownHref, sourceUrl } from "../routing";

type MarkdownPageProps = {
  doc: Doc;
  headings: Heading[];
  activeAnchor: string;
};

function Table({ children }: { children?: ReactNode }) {
  return <div className="table-scroll"><table>{children}</table></div>;
}

export function MarkdownPage({ doc, headings, activeAnchor }: MarkdownPageProps) {
  const currentIndex = docs.findIndex((candidate) => candidate.path === doc.path);
  const previous = docs[currentIndex - 1];
  const next = docs[currentIndex + 1];
  const pageTitle = headings.find((heading) => heading.depth === 1)?.title ?? doc.title;
  const body = doc.content.replace(/^#\s+.+?\n+/, "");
  const components: Components = {
    a({ href, children, ...props }) {
      const resolved = resolveMarkdownHref(doc, href);
      const external = resolved?.startsWith("http");
      return <a href={resolved} target={external ? "_blank" : undefined} rel={external ? "noreferrer" : undefined} {...props}>{children}{external && <ExternalLink className="inline-external" size={12} />}</a>;
    },
    table: Table,
  };

  return (
    <div className="page-grid">
      <main className="content-column" id="main-content">
        <div className="page-kicker">{doc.group}</div>
        <h1 className="page-title">{pageTitle}</h1>
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
            {body}
          </ReactMarkdown>
        </article>
        <nav className="page-pagination" aria-label="Adjacent documentation pages">
          {previous ? <a href={docHref(previous.path)}><small><ChevronLeft size={13} /> Previous</small><strong>{previous.title}</strong></a> : <span />}
          {next && <a className="next" href={docHref(next.path)}><small>Next <ChevronRight size={13} /></small><strong>{next.title}</strong></a>}
        </nav>
        <footer className="content-footer">
          <span>lucid-auth</span> · Better Auth protocol, native Rust execution.
        </footer>
      </main>
      <aside className="toc" aria-label="On this page">
        <h2>On this page</h2>
        <nav>
          {headings.filter((heading) => heading.depth > 1).map((heading) => (
            <a
              className={`${heading.depth === 3 ? "toc-nested" : ""} ${activeAnchor === heading.slug ? "active" : ""}`}
              href={docHref(doc.path, heading.slug)}
              key={heading.slug}
            >
              {heading.title}
            </a>
          ))}
        </nav>
      </aside>
    </div>
  );
}
