import type { LucideIcon } from "lucide-react";

type MetricCardProps = {
  label: string;
  value: string;
  detail: string;
  icon: LucideIcon;
};

export function MetricCard({ label, value, detail, icon: Icon }: MetricCardProps) {
  return (
    <section className="rounded-md border border-zinc-800 bg-zinc-900/70 p-4">
      <div className="flex items-center justify-between gap-3">
        <p className="text-xs font-medium uppercase text-zinc-500">{label}</p>
        <Icon className="size-4 text-cyan-200" aria-hidden="true" />
      </div>
      <p className="mt-3 text-3xl font-semibold tracking-normal text-zinc-50">{value}</p>
      <p className="mt-2 text-sm leading-5 text-zinc-400">{detail}</p>
    </section>
  );
}
