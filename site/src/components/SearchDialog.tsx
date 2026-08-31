import { ArrowRight, Search, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { docs } from "../content";
import { plainText } from "../markdown";
import { docHref } from "../routing";

type SearchDialogProps = {
  open: boolean;
  onClose: () => void;
};

export function SearchDialog({ open, onClose }: SearchDialogProps) {
  const [query, setQuery] = useState("");
  const input = useRef<HTMLInputElement>(null);
  const corpus = useMemo(() => docs.map((doc) => ({ doc, text: plainText(doc.content) })), []);
  const results = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return corpus.slice(0, 6);
    return corpus
      .map(({ doc, text }) => {
        const haystack = `${doc.title} ${doc.description} ${text}`.toLowerCase();
        const index = haystack.indexOf(needle);
        return { doc, text, index };
      })
      .filter((result) => result.index !== -1)
      .sort((left, right) => left.index - right.index)
      .slice(0, 8);
  }, [corpus, query]);

  useEffect(() => {
    if (open) requestAnimationFrame(() => input.current?.focus());
    else setQuery("");
  }, [open]);

  if (!open) return null;

  return (
    <div className="dialog-backdrop" role="presentation" onMouseDown={onClose}>
      <section className="search-dialog" role="dialog" aria-modal="true" aria-label="Search documentation" onMouseDown={(event) => event.stopPropagation()}>
        <div className="search-input-wrap">
          <Search size={20} />
          <input ref={input} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search guides, APIs, and compatibility…" />
          <button className="icon-button" onClick={onClose} aria-label="Close search"><X size={17} /></button>
        </div>
        <div className="search-results">
          {results.length === 0 && <p className="empty-results">No documentation matches “{query}”.</p>}
          {results.map(({ doc }) => (
            <a key={doc.path} href={docHref(doc.path)} onClick={onClose}>
              <span><strong>{doc.title}</strong><small>{doc.description}</small></span>
              <ArrowRight size={16} />
            </a>
          ))}
        </div>
        <footer><kbd>Esc</kbd> to close <span>·</span> Search covers every Markdown guide</footer>
      </section>
    </div>
  );
}
