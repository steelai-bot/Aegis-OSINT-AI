import { Globe2, KeyRound, ScrollText, ShieldCheck } from "lucide-react";

import { MetricCard } from "@/components/metric-card";
import { PageHeader } from "@/components/page-header";
import { ToolApprovalManagement } from "@/components/tool-approval-management";
import { formatDate, titleCase } from "@/lib/format";
import { getToolAuditEventsWithSource, getToolExecutionApprovalsWithSource } from "@/lib/api";
import type { AuditEvent } from "@/lib/types";

export const dynamic = "force-dynamic";

function statusClassName(status: string): string {
  switch (status) {
    case "active":
    case "allowed":
    case "completed":
    case "success":
      return "border-emerald-500/30 bg-emerald-500/10 text-emerald-200";
    case "used":
      return "border-cyan-400/30 bg-cyan-500/10 text-cyan-100";
    case "approval_required":
    case "rate_limited":
      return "border-amber-300/35 bg-amber-400/15 text-amber-100";
    case "revoked":
    case "blocked":
    case "failed":
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

function metadataSummary(metadata: Record<string, unknown>): string {
  const entries = Object.entries(metadata).slice(0, 4);
  if (entries.length === 0) {
    return "No metadata";
  }
  return entries.map(([key, value]) => `${key}: ${String(value)}`).join(" · ");
}

function eventResourceSummary(event: AuditEvent): string {
  if (event.event_type === "tool.execution.egress") {
    const host = String(event.metadata_json.egress_host ?? "unknown host");
    const plugin = String(event.metadata_json.egress_plugin_name ?? event.resource_id ?? "unknown plugin");
    return `host: ${host} · plugin: ${plugin}`;
  }
  return `resource: ${event.resource_id ?? "n/a"}`;
}

export default async function ToolExecutionPage() {
  const [approvalsResult, auditResult] = await Promise.all([
    getToolExecutionApprovalsWithSource(),
    getToolAuditEventsWithSource(),
  ]);
  const approvals = approvalsResult.data;
  const auditEvents = auditResult.data;
  const activeApprovals = approvals.filter((approval) => approval.status === "active").length;
  const egressAuditEvents = auditEvents.filter((event) => event.event_type === "tool.execution.egress");
  const blockedOrRequired = auditEvents.filter((event) => ["blocked", "approval_required", "rate_limited"].includes(event.status)).length;

  return (
    <>
      <PageHeader
        title="Tool Execution"
        description="Review persistent approval grants, execution decisions, outcomes, and per-plugin egress audit events."
        icon={ShieldCheck}
      />

      <div className="grid gap-4 md:grid-cols-4">
        <MetricCard label="Approval grants" value={String(approvals.length)} detail={`${activeApprovals} currently active`} icon={KeyRound} />
        <MetricCard label="Audit events" value={String(auditEvents.length)} detail="tool.execution.* read API" icon={ScrollText} />
        <MetricCard label="Egress events" value={String(egressAuditEvents.length)} detail="sanitized plugin HTTP policy decisions" icon={Globe2} />
        <MetricCard label="Blocked/queued review" value={String(blockedOrRequired)} detail="approval required, blocked, or rate limited" icon={ShieldCheck} />
      </div>

      <ToolApprovalManagement initialApprovals={approvals} source={approvalsResult.source} />

      <section className="rounded-md border border-zinc-800 bg-zinc-900/70">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-800 px-4 py-3">
          <div>
            <h2 className="text-sm font-semibold text-zinc-100">Tool execution audit trail</h2>
            <p className="mt-1 text-xs text-zinc-500">
              Source: {auditResult.source === "live" ? "live API" : "sample fallback"}. Includes persisted egress events with host-only metadata.
            </p>
          </div>
          <ScrollText className="size-4 text-cyan-200" aria-hidden="true" />
        </div>
        <div className="divide-y divide-zinc-800">
          {auditEvents.map((event) => (
            <article key={event.id} className="grid gap-3 px-4 py-4 lg:grid-cols-[240px_140px_1fr_160px] lg:items-start">
              <div>
                <h3 className="font-mono text-sm text-zinc-100">{event.event_type}</h3>
                <p className="mt-1 text-xs text-zinc-500">{eventResourceSummary(event)}</p>
              </div>
              <div><StatusBadge status={event.status} /></div>
              <p className="text-sm leading-6 text-zinc-400">{metadataSummary(event.metadata_json)}</p>
              <div className="text-xs text-zinc-500 lg:text-right">
                <div>{formatDate(event.created_at)}</div>
                <div className="mt-1">actor: {event.actor_id ?? "system"}</div>
              </div>
            </article>
          ))}
        </div>
      </section>
    </>
  );
}