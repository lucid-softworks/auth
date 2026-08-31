import { Code2, Menu, Moon, Search, Sun } from "lucide-react";
import { useEffect, useState } from "react";
import { DocLink } from "./DocLink";

type HeaderProps = {
  onMenu: () => void;
  onSearch: () => void;
};

export function Header({ onMenu, onSearch }: HeaderProps) {
  const [theme, setTheme] = useState(() => document.documentElement.dataset.theme ?? "dark");

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("lucid-docs-theme", theme);
  }, [theme]);

  return (
    <header className="site-header">
      <div className="header-inner">
        <button className="icon-button mobile-only" onClick={onMenu} aria-label="Open navigation">
          <Menu size={19} />
        </button>
        <DocLink className="brand" path="/" ariaLabel="Lucid Auth documentation home">
          <span className="brand-mark">L</span>
          <span>lucid<span className="brand-muted">/auth</span></span>
          <span className="version">v1.7.2</span>
        </DocLink>
        <div className="header-actions">
          <button className="search-trigger" onClick={onSearch} aria-label="Search documentation">
            <Search size={16} />
            <span>Search documentation</span>
            <kbd>⌘ K</kbd>
          </button>
          <a className="icon-button" href="https://github.com/lucid-softworks/auth" aria-label="GitHub repository">
            <Code2 size={18} />
          </a>
          <button
            className="icon-button"
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            aria-label={`Use ${theme === "dark" ? "light" : "dark"} theme`}
          >
            {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
          </button>
        </div>
      </div>
    </header>
  );
}
