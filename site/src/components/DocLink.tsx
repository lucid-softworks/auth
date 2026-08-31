import { Link } from "@tanstack/react-router";
import type { MouseEventHandler, ReactNode } from "react";

type DocLinkProps = {
  path: string;
  anchor?: string;
  children: ReactNode;
  className?: string;
  onClick?: MouseEventHandler<HTMLAnchorElement>;
  ariaCurrent?: "page";
  ariaLabel?: string;
};

export function DocLink({ path, anchor, children, className, onClick, ariaCurrent, ariaLabel }: DocLinkProps) {
  const shared = {
    className,
    hash: anchor || undefined,
    onClick,
    "aria-current": ariaCurrent,
    "aria-label": ariaLabel,
    children,
  };

  if (path === "/") return <Link to="/" {...shared} />;
  return <Link to="/$" params={{ _splat: path.slice(1) }} {...shared} />;
}
