"use client";

import { Copy, KeyRound, Loader2, Trash2, XCircle } from "lucide-react";
import type { FormEvent } from "react";
import { useMemo, useState } from "react";

import { createToolExecutionApproval, isApiConfigured, revokeToolExecutionApproval, type ApiDataSource } from "@/lib/api";
import { formatDate, titleCase } from "@/lib/format";
import type {
  ToolExecutionApproval,
  ToolExecutionApprovalCreatePayload,
  ToolExecutionApprovalCreated,
} from "@/lib/types";

type ToolApprovalManagementProps = {
  initialApprovals: ToolExecutionApproval[];
  source: ApiDataSource;
};

type ApprovalFormState = {
  pluginName: string;
  targetType: string;
  target: string;
  executionMode: ToolExecutionApprovalCreatePayload["execution_mode"];
  authorizedScope: string;
  reason: string;
  requestedBy: string;
  expiresInMinutes: number;
  maxUses: number;
};

const defaultFormState: ApprovalFormState = {
  pluginName: "",
  targetType: "domain",
  target: "",
  executionMode: "operator_assisted",
  authorizedScope: "",
  reason: "",
  requestedBy: "",
  expiresInMinutes: 30,
  maxUses: 1,
};

function statusClassName(status: string): string {
  switch (status) {
    case "active":
      return "border-emerald-500/30 bg-emerald-500/10 text-emerald-200";
    case "used":
      return "border-cyan-400/30 bg-cyan-500/10 text-cyan-100";
    case "revoked":
    case "expired":
      return "border-red-400/40 bg-red-500/15 text-red-100";
    default:
      return "border-zinc-600 bg-zinc-800 text-zinc-300";
  }
}

function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`inline-flex h-6 items-center rounded-full border px-2 text-xs font-medium leading-none ${statusClassName(status)}`}>
      {titleCase(status)}
    </span>
  );
}

function shortHash(value: string | null): string {
  if (!value) {
    return "scope-wide";
  }
  return `${value.slice(0, 10)}…${value.slice(-6)}`;
}

function toApprovalPayload(form: ApprovalFormState): ToolExecutionApprovalCreatePayload {
  return {
    plugin_name: form.pluginName.trim() || undefined,
    target_type: form.targetType.trim() || undefined,
    target: form.target.trim(),
    execution_mode: form.executionMode,
    authorized_scope: form.authorizedScope.trim() || undefined,
    reason: form.reason.trim() || undefined,
    requested_by: form.requestedBy.trim() || undefined,
    expires_in_minutes: form.expiresInMinutes,
    max_uses: form.maxUses,
  };
}

function approvalWithoutToken(created: ToolExecutionApprovalCreated): ToolExecutionApproval {
  const { approval_token, ...approval } = created;
  void approval_token;
  return approval;
}

export function ToolApprovalManagement({ initialApprovals, source }: ToolApprovalManagementProps) {
  const apiReady = isApiConfigured() && source === "live";
  const [approvals, setApprovals] = useState(initialApprovals);
  const [form, setForm] = useState<ApprovalFormState>(defaultFormState);
  const [oneTimeToken, setOneTimeToken] = useState<string | null>(null);
  const [createdApprovalId, setCreatedApprovalId] = useState<string | null>(null);
  const [isCreating, setIsCreating] = useState(false);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copyMessage, setCopyMessage] = useState<string | null>(null);

  const activeApprovals = useMemo(() => approvals.filter((approval) => approval.status === "active").length, [approvals]);

  async function submitApproval(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setCopyMessage(null);
    setOneTimeToken(null);

    if (!apiReady) {
      setError("Live backend API is required to create approvals.");
      return;
    }

    if (!form.target.trim()) {
      setError("Target is required so the approval remains scoped and hash-only at rest.");
      return;
    }

    setIsCreating(true);
    try {
      const created = await createToolExecutionApproval(toApprovalPayload(form));
      setApprovals((current) => [approvalWithoutToken(created), ...current]);
      setOneTimeToken(created.approval_token);
      setCreatedApprovalId(created.id);
      setForm({ ...defaultFormState, targetType: form.targetType, requestedBy: form.requestedBy });
    } catch (createError) {
      setError(createError instanceof Error ? createError.message : "Unable to create approval.");
    } finally {
      setIsCreating(false);
    }
  }

  async function revokeApproval(approvalId: string) {
    setError(null);
    setRevokingId(approvalId);
    try {
      const revoked = await revokeToolExecutionApproval(approvalId);
      setApprovals((current) => current.map((approval) => (approval.id === approvalId ? revoked : approval)));
      if (createdApprovalId === approvalId) {
        setOneTimeToken(null);
        setCreatedApprovalId(null);
      }
    } catch (revokeError) {
      setError(revokeError instanceof Error ? revokeError.message : "Unable to revoke approval.");
    } finally {
      setRevokingId(null);
    }
  }

  async function copyToken() {
    if (!oneTimeToken) {
      return;
    }

    try {
      await navigator.clipboard.writeText(oneTimeToken);
      setCopyMessage("Token copied. Paste it into a collection run now; it will not be shown again after dismissal.");
    } catch {
      setCopyMessage("Clipboard unavailable. Select and copy the token manually.");
    }
  }

  return (
    <section className="rounded-md border border-zinc-800 bg-zinc-900/70">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-800 px-4 py-3">
        <div>
          <h2 className="text-sm font-semibold text-zinc-100">Persistent approvals</h2>
          <p className="mt-1 text-xs text-zinc-500">
            Source: {source === "live" ? "live API" : "sample fallback"}. Create scoped tokens, revoke active grants, and keep raw targets/tokens out of readback.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs text-zinc-500">
          <span>{activeApprovals} active</span>
          <KeyRound className="size-4 text-cyan-200" aria-hidden="true" />
        </div>
      </div>

      <form onSubmit={submitApproval} className="grid gap-3 border-b border-zinc-800 p-4 lg:grid-cols-6">
        <label className="flex flex-col gap-1 text-xs text-zinc-500 lg:col-span-1">
          Plugin
          <input
            value={form.pluginName}
            onChange={(event) => setForm((current) => ({ ...current, pluginName: event.target.value }))}
            placeholder="operator_tool"
            className="h-9 rounded-md border border-zinc-700 bg-zinc-950 px-3 text-sm text-zinc-100 outline-none focus:border-cyan-400/60"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs text-zinc-500 lg:col-span-1">
          Target type
          <input
            value={form.targetType}
            onChange={(event) => setForm((current) => ({ ...current, targetType: event.target.value }))}
            className="h-9 rounded-md border border-zinc-700 bg-zinc-950 px-3 text-sm text-zinc-100 outline-none focus:border-cyan-400/60"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs text-zinc-500 lg:col-span-2">
          Target / scope anchor
          <input
            value={form.target}
            onChange={(event) => setForm((current) => ({ ...current, target: event.target.value }))}
            placeholder="example.com"
            className="h-9 rounded-md border border-zinc-700 bg-zinc-950 px-3 text-sm text-zinc-100 outline-none focus:border-cyan-400/60"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs text-zinc-500 lg:col-span-1">
          Mode
          <select
            value={form.executionMode}
            onChange={(event) =>
              setForm((current) => ({
                ...current,
                executionMode: event.target.value as ToolExecutionApprovalCreatePayload["execution_mode"],
              }))
            }
            className="h-9 rounded-md border border-zinc-700 bg-zinc-950 px-3 text-sm text-zinc-100 outline-none focus:border-cyan-400/60"
          >
            <option value="operator_assisted">Operator assisted</option>
            <option value="manual_review_only">Manual review only</option>
          </select>
        </label>
        <label className="flex flex-col gap-1 text-xs text-zinc-500 lg:col-span-1">
          Uses
          <input
            type="number"
            min={1}
            max={100}
            value={form.maxUses}
            onChange={(event) => setForm((current) => ({ ...current, maxUses: Number(event.target.value) }))}
            className="h-9 rounded-md border border-zinc-700 bg-zinc-950 px-3 text-sm text-zinc-100 outline-none focus:border-cyan-400/60"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs text-zinc-500 lg:col-span-2">
          Authorized scope
          <input
            value={form.authorizedScope}
            onChange={(event) => setForm((current) => ({ ...current, authorizedScope: event.target.value }))}
            placeholder="ticket-123 approved domain verification"
            className="h-9 rounded-md border border-zinc-700 bg-zinc-950 px-3 text-sm text-zinc-100 outline-none focus:border-cyan-400/60"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs text-zinc-500 lg:col-span-2">
          Reason
          <input
            value={form.reason}
            onChange={(event) => setForm((current) => ({ ...current, reason: event.target.value }))}
            placeholder="Operator-approved verification for an authorized target"
            className="h-9 rounded-md border border-zinc-700 bg-zinc-950 px-3 text-sm text-zinc-100 outline-none focus:border-cyan-400/60"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs text-zinc-500 lg:col-span-1">
          Requested by
          <input
            value={form.requestedBy}
            onChange={(event) => setForm((current) => ({ ...current, requestedBy: event.target.value }))}
            placeholder="analyst@example.local"
            className="h-9 rounded-md border border-zinc-700 bg-zinc-950 px-3 text-sm text-zinc-100 outline-none focus:border-cyan-400/60"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs text-zinc-500 lg:col-span-1">
          Expires minutes
          <input
            type="number"
            min={1}
            max={1440}
            value={form.expiresInMinutes}
            onChange={(event) => setForm((current) => ({ ...current, expiresInMinutes: Number(event.target.value) }))}
            className="h-9 rounded-md border border-zinc-700 bg-zinc-950 px-3 text-sm text-zinc-100 outline-none focus:border-cyan-400/60"
          />
        </label>
        <div className="flex flex-col justify-end gap-1 lg:col-span-6">
          <button
            type="submit"
            disabled={!apiReady || isCreating}
            className="inline-flex h-9 w-fit items-center justify-center gap-2 rounded-md bg-cyan-300 px-3 text-xs font-semibold text-zinc-950 transition-colors hover:bg-cyan-200 disabled:cursor-not-allowed disabled:bg-zinc-700 disabled:text-zinc-400"
          >
            {isCreating ? <Loader2 className="size-3.5 animate-spin" aria-hidden="true" /> : <KeyRound className="size-3.5" aria-hidden="true" />}
            Create scoped approval
          </button>
          {!apiReady ? <p className="text-[11px] text-zinc-500">Live API required; sample fallback is read-only.</p> : null}
        </div>
      </form>

      {oneTimeToken ? (
        <div className="border-b border-amber-300/20 bg-amber-400/10 p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-amber-100">One-time approval token</h3>
              <p className="mt-1 text-xs leading-5 text-amber-100/80">
                Copy this token now. Aegis stores only its hash and will not return the plaintext token again.
              </p>
            </div>
            <button type="button" onClick={() => setOneTimeToken(null)} className="text-amber-100/80 hover:text-amber-50" aria-label="Dismiss token">
              <XCircle className="size-4" aria-hidden="true" />
            </button>
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <code className="max-w-full break-all rounded-md border border-amber-300/20 bg-zinc-950 px-3 py-2 text-xs text-amber-50">
              {oneTimeToken}
            </code>
            <button
              type="button"
              onClick={copyToken}
              className="inline-flex h-8 items-center gap-2 rounded-md border border-amber-200/30 px-3 text-xs font-semibold text-amber-50 hover:bg-amber-300/10"
            >
              <Copy className="size-3.5" aria-hidden="true" />
              Copy
            </button>
          </div>
          {copyMessage ? <p className="mt-2 text-xs text-amber-100/80">{copyMessage}</p> : null}
        </div>
      ) : null}

      {error ? <p className="border-b border-red-400/20 bg-red-500/10 px-4 py-3 text-xs text-red-100">{error}</p> : null}

      <div className="overflow-x-auto">
        <table className="w-full min-w-[980px] text-left text-sm">
          <thead className="text-xs uppercase text-zinc-500">
            <tr className="border-b border-zinc-800">
              <th className="px-4 py-3 font-medium">Plugin</th>
              <th className="px-4 py-3 font-medium">Status</th>
              <th className="px-4 py-3 font-medium">Mode</th>
              <th className="px-4 py-3 font-medium">Target hash</th>
              <th className="px-4 py-3 font-medium">Uses</th>
              <th className="px-4 py-3 font-medium">Scope / reason</th>
              <th className="px-4 py-3 font-medium">Expires</th>
              <th className="px-4 py-3 font-medium">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {approvals.map((approval) => (
              <tr key={approval.id}>
                <td className="px-4 py-3">
                  <div className="font-medium text-zinc-100">{approval.plugin_name ?? "any plugin"}</div>
                  <div className="mt-1 text-xs text-zinc-500">{approval.target_type ?? "any target type"}</div>
                </td>
                <td className="px-4 py-3"><StatusBadge status={approval.status} /></td>
                <td className="px-4 py-3 font-mono text-xs text-zinc-300">{approval.execution_mode}</td>
                <td className="px-4 py-3 font-mono text-xs text-zinc-400">{shortHash(approval.target_hash)}</td>
                <td className="px-4 py-3 font-mono text-zinc-300">{approval.use_count}/{approval.max_uses}</td>
                <td className="max-w-md px-4 py-3 text-zinc-400">
                  <div>{approval.authorized_scope ?? "No scope note"}</div>
                  <div className="mt-1 text-xs text-zinc-500">{approval.reason ?? "No reason supplied"}</div>
                </td>
                <td className="px-4 py-3 text-zinc-500">{formatDate(approval.expires_at)}</td>
                <td className="px-4 py-3">
                  <button
                    type="button"
                    onClick={() => void revokeApproval(approval.id)}
                    disabled={!apiReady || approval.status !== "active" || revokingId === approval.id}
                    className="inline-flex h-8 items-center gap-2 rounded-md border border-red-400/30 px-2 text-xs font-semibold text-red-100 hover:bg-red-500/10 disabled:cursor-not-allowed disabled:border-zinc-700 disabled:text-zinc-600"
                  >
                    {revokingId === approval.id ? <Loader2 className="size-3.5 animate-spin" aria-hidden="true" /> : <Trash2 className="size-3.5" aria-hidden="true" />}
                    Revoke
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}