import { useEffect, useMemo, useState } from "react";
import { Header } from "./components/Header";
import { MarkdownPage } from "./components/MarkdownPage";
import { SearchDialog } from "./components/SearchDialog";
import { Sidebar } from "./components/Sidebar";
import { docs, docsByPath } from "./content";
import { extractHeadings } from "./markdown";
import { readLocation } from "./routing";

export default function App() {
  const [location, setLocation] = useState(readLocation);
  const [menuOpen, setMenuOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const doc = docsByPath.get(location.path) ?? docs[0];
  const headings = useMemo(() => extractHeadings(doc.content), [doc]);
  const [activeAnchor, setActiveAnchor] = useState(location.anchor);

  useEffect(() => {
    const onHashChange = () => setLocation(readLocation());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  useEffect(() => {
    document.title = `${doc.title} · Lucid Auth`;
    setActiveAnchor(location.anchor);
    requestAnimationFrame(() => {
      if (location.anchor) document.getElementById(location.anchor)?.scrollIntoView();
      else window.scrollTo({ top: 0 });
    });
  }, [doc, location.anchor]);

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
    const elements = headings
      .filter((heading) => heading.depth > 1)
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

  return (
    <>
      <a className="skip-link" href="#main-content">Skip to content</a>
      <Header onMenu={() => setMenuOpen(true)} onSearch={() => setSearchOpen(true)} />
      <Sidebar activePath={doc.path} open={menuOpen} onClose={() => setMenuOpen(false)} />
      <div className="site-main">
        <MarkdownPage doc={doc} headings={headings} activeAnchor={activeAnchor} />
      </div>
      <SearchDialog open={searchOpen} onClose={() => setSearchOpen(false)} />
    </>
  );
}
