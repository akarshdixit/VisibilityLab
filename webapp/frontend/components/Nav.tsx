"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const ITEMS = [
  ["/", "Overview"],
  ["/new", "New Analysis"],
  ["/samples", "Samples"],
  ["/evidence", "Evidence / Audit"],
  ["/exports", "Exports"],
  ["/settings", "Settings"],
] as const;

export function Nav() {
  const path = usePathname();
  return (
    <nav className="nav">
      {ITEMS.map(([href, label]) => {
        const active = href === "/" ? path === "/" : path.startsWith(href) || (href === "/samples" && path.startsWith("/analyses"));
        return (
          <Link key={href} href={href} className={active ? "active" : undefined}>
            {label}
          </Link>
        );
      })}
    </nav>
  );
}
