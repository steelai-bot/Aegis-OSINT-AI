import type { LucideIcon } from "lucide-react";

type PageHeaderProps = {
  title: string;
  description: string;
  icon: LucideIcon;
  action?: React.ReactNode;
};

export function PageHeader({ title, description, icon: Icon, action }: PageHeaderProps) {
  return (
    <header className="flex flex-col gap-4 border-b border-zinc-800/80 pb-5 sm:flex-row sm:items-end sm:justify-between">
      <div className="flex items-start gap-3">
        <div className="grid size-10 shrink-0 place-items-center rounded-md border border-zinc-700 bg-zinc-900 text-cyan-200">
          <Icon className="size-5" aria-hidden="true" />
        </div>
        <div>
          <h1 className="text-2xl font-semibold tracking-normal text-zinc-50">{title}</h1>
          <p className="mt-1 max-w-3xl text-sm leading-6 text-zinc-400">{description}</p>
        </div>
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </header>
  );
}
