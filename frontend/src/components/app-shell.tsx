"use client";

import {
  Activity,
  ChartNoAxesCombined,
  FileText,
  Flag,
  LayoutDashboard,
  Plug,
  ScrollText,
  Search,
  Settings,
  ShieldCheck,
  Target,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

const navItems = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/investigations", label: "Investigations", icon: Search },
  { href: "/targets", label: "Targets", icon: Target },
  { href: "/findings", label: "Findings", icon: Flag },
  { href: "/reports", label: "Reports", icon: FileText },
  { href: "/plugins", label: "Plugins", icon: Plug },
  { href: "/tool-execution", label: "Tool Execution", icon: ScrollText },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <div className="grid min-h-screen lg:grid-cols-[248px_1fr]">
        <aside className="border-b border-zinc-800 bg-zinc-950/95 lg:border-b-0 lg:border-r">
          <div className="flex h-full flex-col">
            <div className="flex h-16 items-center gap-3 border-b border-zinc-800 px-5">
              <div className="grid size-9 place-items-center rounded-md bg-cyan-300 text-zinc-950">
                <ShieldCheck className="size-5" aria-hidden="true" />
              </div>
              <div>
                <p className="text-sm font-semibold leading-5 text-zinc-50">Aegis OSINT</p>
                <p className="text-xs leading-4 text-zinc-500">Passive intel console</p>
              </div>
            </div>
            <nav className="flex gap-1 overflow-x-auto px-3 py-3 lg:flex-col lg:overflow-visible">
              {navItems.map((item) => {
                const active = pathname === item.href || (pathname === "/" && item.href === "/dashboard");
                const Icon = item.icon;

                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={`flex h-10 min-w-fit items-center gap-3 rounded-md px-3 text-sm font-medium transition-colors ${
                      active
                        ? "bg-zinc-800 text-cyan-100"
                        : "text-zinc-400 hover:bg-zinc-900 hover:text-zinc-100"
                    }`}
                  >
                    <Icon className="size-4" aria-hidden="true" />
                    {item.label}
                  </Link>
                );
              })}
            </nav>
            <div className="mt-auto hidden border-t border-zinc-800 p-4 lg:block">
              <div className="rounded-md border border-zinc-800 bg-zinc-900/70 p-3">
                <div className="flex items-center gap-2 text-xs font-medium text-zinc-300">
                  <Activity className="size-4 text-emerald-300" aria-hidden="true" />
                  Passive mode
                </div>
                <p className="mt-2 text-xs leading-5 text-zinc-500">
                  Workflows are designed for lawful passive collection and operator-reviewed reporting.
                </p>
              </div>
            </div>
          </div>
        </aside>
        <div className="min-w-0">
          <header className="flex h-16 items-center justify-between border-b border-zinc-800 bg-zinc-950/95 px-4 sm:px-6">
            <div className="flex items-center gap-2 text-sm text-zinc-400">
              <ChartNoAxesCombined className="size-4 text-cyan-200" aria-hidden="true" />
              <span>Operational workspace</span>
            </div>
            <div className="flex items-center gap-2 text-xs text-zinc-500">
              <span className="size-2 rounded-full bg-emerald-300" aria-hidden="true" />
              API-ready
            </div>
          </header>
          <main className="mx-auto flex w-full max-w-7xl flex-col gap-6 px-4 py-6 sm:px-6 lg:px-8">{children}</main>
        </div>
      </div>
    </div>
  );
}
