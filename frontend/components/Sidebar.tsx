"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";

const NAV = [
  { href: "/", label: "Overview", icon: "▦" },
  { href: "/incidents", label: "Incidents", icon: "✦" },
  { href: "/graph", label: "Memory Graph", icon: "⬡" },
  { href: "/investigations", label: "Investigations", icon: "⌕" },
  { href: "/predictions", label: "Threat Predictions", icon: "◈" },
];

export function Sidebar() {
  const path = usePathname();
  return (
    <aside className="w-56 shrink-0 border-r border-edge bg-panel min-h-screen p-4">
      <div className="mb-8">
        <div className="text-lg font-semibold tracking-tight">
          SOC <span className="text-accent">PARALLAX</span>
        </div>
        <div className="text-[10px] text-muted uppercase tracking-widest">
          Behavioral Intelligence
        </div>
      </div>
      <nav className="space-y-1">
        {NAV.map((n) => {
          const active = path === n.href || (n.href !== "/" && path.startsWith(n.href));
          return (
            <Link
              key={n.href}
              href={n.href}
              className={`flex items-center gap-3 px-3 py-2 rounded text-sm transition ${
                active ? "bg-panel2 text-accent" : "text-muted hover:text-white hover:bg-panel2"
              }`}
            >
              <span className="w-4 text-center">{n.icon}</span>
              {n.label}
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
