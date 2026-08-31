import { BookOpen, Code2, ExternalLink, X } from "lucide-react";
import { docs } from "../content";
import { docHref } from "../routing";

type SidebarProps = {
  activePath: string;
  open: boolean;
  onClose: () => void;
};

const groups = ["Overview", "Guides", "Reference"] as const;

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
              {docs.filter((doc) => doc.group === group).map((doc) => (
                <a
                  key={doc.path}
                  href={docHref(doc.path)}
                  className={activePath === doc.path ? "active" : ""}
                  onClick={onClose}
                >
                  {doc.title}
                </a>
              ))}
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
