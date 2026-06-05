import { titleCase } from "@/lib/format";
import type { Finding, InvestigationStatus, PluginStatus } from "@/lib/types";

type StatusValue = InvestigationStatus | Finding["severity"] | PluginStatus["status"];

const statusClassName: Record<StatusValue, string> = {
  completed: "border-emerald-500/30 bg-emerald-500/10 text-emerald-200",
  critical: "border-red-400/40 bg-red-500/15 text-red-100",
  disabled: "border-zinc-600 bg-zinc-800 text-zinc-300",
  enabled: "border-emerald-500/30 bg-emerald-500/10 text-emerald-200",
  failed: "border-red-400/40 bg-red-500/15 text-red-100",
  high: "border-orange-400/40 bg-orange-500/15 text-orange-100",
  info: "border-sky-400/35 bg-sky-500/15 text-sky-100",
  low: "border-cyan-400/30 bg-cyan-500/10 text-cyan-100",
  medium: "border-amber-300/35 bg-amber-400/15 text-amber-100",
  needs_key: "border-amber-300/35 bg-amber-400/15 text-amber-100",
  queued: "border-zinc-500/40 bg-zinc-700/35 text-zinc-200",
  running: "border-blue-400/35 bg-blue-500/15 text-blue-100",
};

export function StatusPill({ value }: { value: StatusValue }) {
  return (
    <span
      className={`inline-flex h-6 items-center rounded-full border px-2 text-xs font-medium leading-none ${statusClassName[value]}`}
    >
      {titleCase(value)}
    </span>
  );
}
