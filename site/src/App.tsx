import { useNavigate, useRouterState } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { Header } from "./components/Header";
import { MarkdownPage } from "./components/MarkdownPage";
import { SearchDialog } from "./components/SearchDialog";
import { Sidebar } from "./components/Sidebar";
import { docsByPath } from "./content";
import { extractHeadings } from "./markdown";
import { legacyLocation, legacyPathLocation, normalizeDocPath, type DocLocation } from "./routing";

export default function App() {
  const location = useRouterState({ select: (state) => state.location });
  const navigate = useNavigate();
  const path = normalizeDocPath(location.pathname);
  const doc = docsByPath.get(path);
  const [menuOpen, setMenuOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const headings = useMemo(() => extractHeadings(doc?.content ?? ""), [doc]);
  const [activeAnchor, setActiveAnchor] = useState(location.hash);

  useEffect(() => {
    const target = legacyLocation(window.location.hash) ??
      (!doc ? legacyPathLocation(path, location.hash) : undefined);
    if (!target) return;
    const options = { hash: target.anchor || undefined, replace: true } as const;
    if (target.path === "/") void navigate({ to: "/", ...options });
    else void navigate({ to: "/$", params: { _splat: target.path.slice(1) }, ...options });
  }, [doc, location.hash, navigate, path]);

  useEffect(() => {
    document.title = doc ? `${doc.title} · Lucid Auth` : "Page not found · Lucid Auth";
    setActiveAnchor(location.hash);
    requestAnimationFrame(() => {
      if (location.hash) document.getElementById(location.hash)?.scrollIntoView();
      else window.scrollTo({ top: 0 });
    });
  }, [doc, location.hash]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setSearchOpen(true);
      }
      if (event.key === "Escape") {
        setSearchOpen(false);
        setMenuOpen(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  useEffect(() => {
    if (!doc) return;
    const elements = headings
      .map((heading) => document.getElementById(heading.slug))
      .filter((element): element is HTMLElement => element !== null);
    if (!elements.length) return;
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries.find((entry) => entry.isIntersecting);
        if (visible) setActiveAnchor(visible.target.id);
      },
      { rootMargin: "-96px 0px -70%", threshold: 0 },
    );
    elements.forEach((element) => observer.observe(element));
    return () => observer.disconnect();
  }, [doc, headings]);

  const navigateTo = (target: DocLocation) => {
    if (target.path === "/") void navigate({ to: "/", hash: target.anchor || undefined });
    else void navigate({ to: "/$", params: { _splat: target.path.slice(1) }, hash: target.anchor || undefined });
  };

  return (
    <>
      <a className="skip-link" href="#main-content">Skip to content</a>
      <Header onMenu={() => setMenuOpen(true)} onSearch={() => setSearchOpen(true)} />
      <Sidebar activePath={doc?.path ?? path} open={menuOpen} onClose={() => setMenuOpen(false)} />
      <div className="site-main">
        {doc ? (
          <MarkdownPage doc={doc} headings={headings} activeAnchor={activeAnchor} />
        ) : (
          <main className="not-found" id="main-content">
            <span>404</span>
            <h1>That documentation page does not exist.</h1>
            <p>The guide may have moved when the documentation was split into focused sections.</p>
            <button onClick={() => navigateTo({ path: "/", anchor: "" })}>Return to the introduction</button>
          </main>
        )}
      </div>
      <SearchDialog open={searchOpen} onClose={() => setSearchOpen(false)} />
    </>
  );
}
