"use client";

import { Loader2, Play, RefreshCw } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { StatusPill } from "@/components/status-pill";
import {
  getCollectionRunStatus,
  isApiConfigured,
  queueInvestigationCollection,
  queueTargetCollection,
} from "@/lib/api";
import { formatDate } from "@/lib/format";
import type { CollectionRunStatus, CollectionRunStatusValue } from "@/lib/types";

type CollectionRunControlProps = {
  scope: "target" | "investigation";
  entityId: string;
  disabledReason?: string;
};

const terminalStatuses: CollectionRunStatusValue[] = ["completed", "failed"];

export function CollectionRunControl({ scope, entityId, disabledReason }: CollectionRunControlProps) {
  const apiReady = isApiConfigured();
  const [runId, setRunId] = useState<string | null>(null);
  const [status, setStatus] = useState<CollectionRunStatusValue | null>(null);
  const [runStatus, setRunStatus] = useState<CollectionRunStatus | null>(null);
  const [isQueueing, setIsQueueing] = useState(false);
  const [isPolling, setIsPolling] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canPoll = useMemo(() => Boolean(runId && status && !terminalStatuses.includes(status)), [runId, status]);

  useEffect(() => {
    if (!runId || !canPoll) {
      return;
    }

    let cancelled = false;

    async function pollStatus() {
      setIsPolling(true);
      try {
        const nextStatus = await getCollectionRunStatus(runId as string);
        if (cancelled) {
          return;
        }
        setRunStatus(nextStatus);
        setStatus(nextStatus.status);
        setError(null);
      } catch (pollError) {
        if (!cancelled) {
          setError(pollError instanceof Error ? pollError.message : "Unable to poll collection run status.");
        }
      } finally {
        if (!cancelled) {
          setIsPolling(false);
        }
      }
    }

    void pollStatus();
    const intervalId = window.setInterval(() => void pollStatus(), 4000);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, [canPoll, runId]);

  async function queueRun() {
    if (!apiReady) {
      setError("Set NEXT_PUBLIC_AEGIS_API_URL to enable live async collection.");
      return;
    }

    setIsQueueing(true);
    setError(null);
    setRunStatus(null);

    try {
      const queued =
        scope === "target"
          ? await queueTargetCollection(entityId, { async_mode: true })
          : await queueInvestigationCollection(entityId, { async_mode: true });

      setRunId(queued.run_id);
      setStatus(queued.status);
    } catch (queueError) {
      setError(queueError instanceof Error ? queueError.message : "Unable to queue collection run.");
    } finally {
      setIsQueueing(false);
    }
  }

  return (
    <div className="flex min-w-[220px] flex-col gap-2">
      <button
        type="button"
        onClick={queueRun}
        disabled={isQueueing || !apiReady || Boolean(disabledReason)}
        className="inline-flex h-9 items-center justify-center gap-2 rounded-md border border-cyan-400/30 bg-cyan-400/10 px-3 text-xs font-semibold text-cyan-100 transition-colors hover:bg-cyan-400/15 disabled:cursor-not-allowed disabled:border-zinc-700 disabled:bg-zinc-800/60 disabled:text-zinc-500"
      >
        {isQueueing ? <Loader2 className="size-3.5 animate-spin" aria-hidden="true" /> : <Play className="size-3.5" aria-hidden="true" />}
        Run async collection
      </button>

      <div className="min-h-6 text-xs text-zinc-500">
        {disabledReason ? <span>{disabledReason}</span> : null}
        {!disabledReason && !apiReady ? <span>Offline: configure API URL</span> : null}
        {status ? (
          <div className="flex flex-wrap items-center gap-2">
            <StatusPill value={status} />
            {isPolling ? <RefreshCw className="size-3 animate-spin text-blue-200" aria-label="Polling status" /> : null}
          </div>
        ) : null}
      </div>

      {runId ? <p className="break-all font-mono text-[11px] leading-4 text-zinc-500">Run: {runId}</p> : null}
      {runStatus?.completed_at ? <p className="text-[11px] text-zinc-500">Completed {formatDate(runStatus.completed_at)}</p> : null}
      {typeof runStatus?.persisted_count === "number" && terminalStatuses.includes(runStatus.status) ? (
        <p className="text-[11px] text-zinc-500">Persisted findings: {runStatus.persisted_count}</p>
      ) : null}
      {error ? <p className="text-[11px] leading-4 text-red-200">{error}</p> : null}
    </div>
  );
}