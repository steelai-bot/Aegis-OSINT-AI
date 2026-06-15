import { Activity, Clock, Database } from "lucide-react";

import { StatusPill } from "@/components/status-pill";
import { formatDate } from "@/lib/format";
import type { ApiDataSource } from "@/lib/api";
import type { CollectionRunStatus } from "@/lib/types";

type RecentCollectionRunsProps = {
  runs: CollectionRunStatus[];
  source: ApiDataSource;
};

function runLabel(run: CollectionRunStatus): string {
  if (run.target) {
    return run.target;
  }
  if (run.run_scope === "investigation") {
    return "Investigation-wide collection";
  }
  return "Ad hoc collection";
}

export function RecentCollectionRuns({ runs, source }: RecentCollectionRunsProps) {
  return (
    <section className="rounded-md border border-zinc-800 bg-zinc-900/70">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-800 px-4 py-3">
        <div>
          <h2 className="text-sm font-semibold text-zinc-100">Recent collection runs</h2>
          <p className="mt-1 text-xs text-zinc-500">
            {source === "live" ? "Live persisted run history" : "Sample run history — configure API URL for live status"}
          </p>
        </div>
        <Activity className="size-4 text-cyan-200" aria-hidden="true" />
      </div>

      {runs.length === 0 ? (
        <div className="px-4 py-8 text-sm text-zinc-500">No collection runs have been queued yet.</div>
      ) : (
        <div className="divide-y divide-zinc-800">
          {runs.map((run) => (
            <article key={run.run_id} className="grid gap-3 px-4 py-3 text-sm sm:grid-cols-[1fr_auto]">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <StatusPill value={run.status} />
                  <span className="rounded-full border border-zinc-700 px-2 py-0.5 text-[11px] uppercase tracking-wide text-zinc-400">
                    {run.run_scope}
                  </span>
                  {run.plugin_name ? (
                    <span className="rounded-full border border-cyan-400/20 bg-cyan-400/10 px-2 py-0.5 text-[11px] text-cyan-100">
                      {run.plugin_name}
                    </span>
                  ) : null}
                </div>
                <p className="mt-2 truncate font-medium text-zinc-100">{runLabel(run)}</p>
                <p className="mt-1 break-all font-mono text-[11px] text-zinc-500">{run.run_id}</p>
              </div>

              <div className="grid gap-1 text-xs text-zinc-500 sm:min-w-[180px] sm:text-right">
                <span className="inline-flex items-center gap-1 sm:justify-end">
                  <Clock className="size-3" aria-hidden="true" />
                  {formatDate(run.updated_at)}
                </span>
                <span className="inline-flex items-center gap-1 sm:justify-end">
                  <Database className="size-3" aria-hidden="true" />
                  {run.persisted_count} persisted finding{run.persisted_count === 1 ? "" : "s"}
                </span>
                {Object.keys(run.errors ?? {}).length > 0 ? <span className="text-red-200">Errors recorded</span> : null}
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}