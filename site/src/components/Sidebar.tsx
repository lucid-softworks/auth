import { BookOpen, Code2, ExternalLink, X } from "lucide-react";
import { docs, sourceRoots } from "../content";
import { DocLink } from "./DocLink";

type SidebarProps = {
  activePath: string;
  open: boolean;
  onClose: () => void;
};

const groups = ["Overview", "Guides", "Reference"] as const;

function inBranch(activePath: string, path: string) {
  return activePath === path || activePath.startsWith(`${path}/`);
}

export function Sidebar({ activePath, open, onClose }: SidebarProps) {
  return (
    <>
      {open && <button className="sidebar-backdrop" onClick={onClose} aria-label="Close navigation" />}
      <aside className={`sidebar ${open ? "sidebar-open" : ""}`} aria-label="Documentation navigation">
        <div className="mobile-sidebar-heading">
          <span>Documentation</span>
          <button className="icon-button" onClick={onClose} aria-label="Close navigation"><X size={18} /></button>
        </div>
        <nav>
          {groups.map((group) => (
            <section className="nav-group" key={group}>
              <h2>{group}</h2>
              {sourceRoots.filter((root) => root.group === group).map((root) => {
                const activeSource = inBranch(activePath, root.path === "/" ? "/overview" : root.path) || activePath === root.path;
                const sections = docs.filter((doc) => doc.source === root.source && doc.depth === 2);
                return (
                  <div className="nav-source" key={root.path}>
                    <DocLink
                      path={root.path}
                      className={activePath === root.path ? "active nav-root" : "nav-root"}
                      ariaCurrent={activePath === root.path ? "page" : undefined}
                      onClick={onClose}
                    >
                      {root.title}
                    </DocLink>
                    {activeSource && sections.map((section) => {
                      const activeSection = inBranch(activePath, section.path);
                      const children = docs.filter((doc) => doc.parentPath === section.path && doc.depth === 3);
                      return (
                        <div key={section.path}>
                          <DocLink
                            path={section.path}
                            className={activePath === section.path ? "active nav-section" : "nav-section"}
                            ariaCurrent={activePath === section.path ? "page" : undefined}
                            onClick={onClose}
                          >
                            {section.title}
                          </DocLink>
                          {activeSection && children.map((child) => (
                            <DocLink
                              path={child.path}
                              className={activePath === child.path ? "active nav-subsection" : "nav-subsection"}
                              ariaCurrent={activePath === child.path ? "page" : undefined}
                              onClick={onClose}
                              key={child.path}
                            >
                              {child.title}
                            </DocLink>
                          ))}
                        </div>
                      );
                    })}
                  </div>
                );
              })}
            </section>
          ))}
        </nav>
        <div className="sidebar-links">
          <a href="https://github.com/lucid-softworks/auth"><Code2 size={15} /> Repository <ExternalLink size={12} /></a>
          <a href="https://crates.io/crates/lucid-auth"><BookOpen size={15} /> crates.io <ExternalLink size={12} /></a>
        </div>
      </aside>
    </>
  );
}
