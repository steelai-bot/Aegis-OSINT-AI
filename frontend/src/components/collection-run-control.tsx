"use client";

import { ChevronDown, ChevronUp, Loader2, Play, RefreshCw, ShieldCheck } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { StatusPill } from "@/components/status-pill";
import {
  getCollectionRunStatus,
  isApiConfigured,
  queueInvestigationCollection,
  queueTargetCollection,
} from "@/lib/api";
import { formatDate } from "@/lib/format";
import type { CollectionRunStatus, CollectionRunStatusValue, CollectionWorkflowPayload, ToolExecutionMode } from "@/lib/types";

type CollectionRunControlProps = {
  scope: "target" | "investigation";
  entityId: string;
  disabledReason?: string;
};

const terminalStatuses: CollectionRunStatusValue[] = ["completed", "failed"];

type ExecutionControlState = {
  pluginName: string;
  executionMode: Exclude<ToolExecutionMode, "disabled">;
  authorizedScope: string;
  approvalToken: string;
};

const defaultExecutionControlState: ExecutionControlState = {
  pluginName: "",
  executionMode: "passive",
  authorizedScope: "",
  approvalToken: "",
};

function buildCollectionPayload(state: ExecutionControlState): CollectionWorkflowPayload {
  return {
    async_mode: true,
    plugin_name: state.pluginName.trim() || undefined,
    execution_mode: state.executionMode,
    authorized_scope: state.authorizedScope.trim() || undefined,
    approval_token: state.approvalToken.trim() || undefined,
  };
}

export function CollectionRunControl({ scope, entityId, disabledReason }: CollectionRunControlProps) {
  const apiReady = isApiConfigured();
  const [runId, setRunId] = useState<string | null>(null);
  const [status, setStatus] = useState<CollectionRunStatusValue | null>(null);
  const [runStatus, setRunStatus] = useState<CollectionRunStatus | null>(null);
  const [isQueueing, setIsQueueing] = useState(false);
  const [isPolling, setIsPolling] = useState(false);
  const [showControls, setShowControls] = useState(false);
  const [controls, setControls] = useState<ExecutionControlState>(defaultExecutionControlState);
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
      const payload = buildCollectionPayload(controls);
      const queued =
        scope === "target"
          ? await queueTargetCollection(entityId, payload)
          : await queueInvestigationCollection(entityId, payload);

      setRunId(queued.run_id);
      setStatus(queued.status);
      setControls((current) => ({ ...current, approvalToken: "" }));
    } catch (queueError) {
      setError(queueError instanceof Error ? queueError.message : "Unable to queue collection run.");
    } finally {
      setIsQueueing(false);
    }
  }

  return (
    <div className="flex min-w-[260px] flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={queueRun}
          disabled={isQueueing || !apiReady || Boolean(disabledReason)}
          className="inline-flex h-9 items-center justify-center gap-2 rounded-md border border-cyan-400/30 bg-cyan-400/10 px-3 text-xs font-semibold text-cyan-100 transition-colors hover:bg-cyan-400/15 disabled:cursor-not-allowed disabled:border-zinc-700 disabled:bg-zinc-800/60 disabled:text-zinc-500"
        >
          {isQueueing ? <Loader2 className="size-3.5 animate-spin" aria-hidden="true" /> : <Play className="size-3.5" aria-hidden="true" />}
          Run async collection
        </button>
        <button
          type="button"
          onClick={() => setShowControls((current) => !current)}
          className="inline-flex h-9 items-center justify-center gap-2 rounded-md border border-zinc-700 bg-zinc-900 px-2 text-xs font-semibold text-zinc-300 transition-colors hover:border-zinc-600 hover:bg-zinc-800"
          aria-expanded={showControls}
        >
          <ShieldCheck className="size-3.5" aria-hidden="true" />
          Controls
          {showControls ? <ChevronUp className="size-3.5" aria-hidden="true" /> : <ChevronDown className="size-3.5" aria-hidden="true" />}
        </button>
      </div>

      {showControls ? (
        <div className="grid gap-2 rounded-md border border-zinc-800 bg-zinc-950/60 p-3">
          <label className="flex flex-col gap-1 text-[11px] text-zinc-500">
            Plugin override
            <input
              value={controls.pluginName}
              onChange={(event) => setControls((current) => ({ ...current, pluginName: event.target.value }))}
              placeholder="optional plugin_name"
              className="h-8 rounded-md border border-zinc-700 bg-zinc-950 px-2 text-xs text-zinc-100 outline-none focus:border-cyan-400/60"
            />
          </label>
          <label className="flex flex-col gap-1 text-[11px] text-zinc-500">
            Execution mode
            <select
              value={controls.executionMode}
              onChange={(event) =>
                setControls((current) => ({ ...current, executionMode: event.target.value as ExecutionControlState["executionMode"] }))
              }
              className="h-8 rounded-md border border-zinc-700 bg-zinc-950 px-2 text-xs text-zinc-100 outline-none focus:border-cyan-400/60"
            >
              <option value="passive">Passive</option>
              <option value="operator_assisted">Operator assisted</option>
              <option value="manual_review_only">Manual review only</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-[11px] text-zinc-500">
            Authorized scope
            <input
              value={controls.authorizedScope}
              onChange={(event) => setControls((current) => ({ ...current, authorizedScope: event.target.value }))}
              placeholder="ticket / scope note"
              className="h-8 rounded-md border border-zinc-700 bg-zinc-950 px-2 text-xs text-zinc-100 outline-none focus:border-cyan-400/60"
            />
          </label>
          <label className="flex flex-col gap-1 text-[11px] text-zinc-500">
            Approval token
            <input
              type="password"
              value={controls.approvalToken}
              onChange={(event) => setControls((current) => ({ ...current, approvalToken: event.target.value }))}
              placeholder="paste one-time token only when needed"
              autoComplete="off"
              className="h-8 rounded-md border border-zinc-700 bg-zinc-950 px-2 text-xs text-zinc-100 outline-none focus:border-cyan-400/60"
            />
          </label>
          <p className="text-[11px] leading-4 text-zinc-500">
            Tokens are sent only with this queue request and cleared from the form after submit.
          </p>
        </div>
      ) : null}

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