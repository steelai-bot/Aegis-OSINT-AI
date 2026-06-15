"use client";

import { useEffect, useState } from "react";
import { Activity, Server, Clock, CheckCircle, AlertTriangle, RefreshCw } from "lucide-react";
import { getWorkerStatusWithSource, type WorkerStatusResult } from "@/lib/api";
import { PageHeader } from "@/components/page-header";
import { MetricCard } from "@/components/metric-card";

export default function WorkersPage() {
  const [data, setData] = useState<WorkerStatusResult | null>(null);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const result = await getWorkerStatusWithSource();
      setData(result.data);
    } catch {
      // fallback
    }
    setLoading(false);
  };

  useEffect(() => {
    load();
  }, []);

  const status = data?.status;
  const metrics = data?.metrics;

  return (
    <>
      <PageHeader title="Worker Monitor" subtitle="Distributed queue status and job metrics" />
      <div className="flex items-center gap-2 mb-4">
        <button
          onClick={load}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-md border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-xs font-medium text-zinc-300 hover:bg-zinc-700 disabled:opacity-50"
        >
          <RefreshCw className={`size-3.5 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          label="Queue Backend"
          value={status?.queue_backend ?? "—"}
          icon={<Server className="size-5 text-cyan-300" />}
        />
        <MetricCard
          label="Queue Health"
          value={metrics?.queue_health ?? "—"}
          icon={<Activity className={`size-5 ${metrics?.queue_health === "healthy" ? "text-emerald-300" : "text-amber-300"}`} />}
        />
        <MetricCard
          label="Active Workers"
          value={String(metrics?.active_workers ?? 0)}
          icon={<CheckCircle className="size-5 text-emerald-300" />}
        />
        <MetricCard
          label="Job Timeout"
          value={`${status?.job_timeout_seconds ?? 0}s`}
          icon={<Clock className="size-5 text-blue-300" />}
        />
      </div>

      <div className="mt-6 rounded-md border border-zinc-800 bg-zinc-900/70 p-4">
        <h3 className="text-sm font-semibold text-zinc-300 mb-3">Job Statistics</h3>
        <div className="grid gap-4 sm:grid-cols-3">
          <div>
            <p className="text-xs text-zinc-500">Total Jobs</p>
            <p className="text-xl font-bold text-zinc-100">{metrics?.total_jobs ?? 0}</p>
          </div>
          <div>
            <p className="text-xs text-zinc-500">Successful</p>
            <p className="text-xl font-bold text-emerald-300">{metrics?.successful_jobs ?? 0}</p>
          </div>
          <div>
            <p className="text-xs text-zinc-500">Failed</p>
            <p className="text-xl font-bold text-red-300">{metrics?.failed_jobs ?? 0}</p>
          </div>
        </div>
      </div>

      <div className="mt-6 rounded-md border border-zinc-800 bg-zinc-900/70 p-4">
        <h3 className="text-sm font-semibold text-zinc-300 mb-3">Configuration</h3>
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <p className="text-xs text-zinc-500">Max Retries</p>
            <p className="text-lg font-semibold text-zinc-100">{status?.max_retries ?? 0}</p>
          </div>
          <div>
            <p className="text-xs text-zinc-500">Redis URL</p>
            <p className="text-lg font-semibold text-zinc-100 break-all">{status?.redis_url ?? "Not configured"}</p>
          </div>
        </div>
        {status?.status !== "healthy" && (
          <div className="mt-3 flex items-center gap-2 rounded border border-amber-800 bg-amber-950/30 p-2 text-xs text-amber-200">
            <AlertTriangle className="size-3.5" />
            Worker status: {status?.status}
          </div>
        )}
      </div>
    </>
  );
}