import { AlertTriangle, FileText, Flag, Search, Target } from "lucide-react";

import { LiveTimeline } from "@/components/live-timeline";
import { MetricCard } from "@/components/metric-card";
import { PageHeader } from "@/components/page-header";
import { StatusPill } from "@/components/status-pill";
import { formatDate, formatPercent } from "@/lib/format";
import { getFindings, getInvestigations, getReports, getTargets, getTimelineEvents } from "@/lib/api";

export default async function DashboardPage() {
  const [investigations, targets, findings, reports] = await Promise.all([
    getInvestigations(),
    getTargets(),
    getFindings(),
    getReports(),
  ]);
  const runningCount = investigations.filter((investigation) => investigation.status === "running").length;
  const highRiskCount = findings.filter((finding) => ["high", "critical"].includes(finding.severity)).length;
  const latestFindings = findings.slice(0, 5);

  return (
    <>
      <PageHeader
        title="Dashboard"
        description="Monitor passive OSINT workflows, finding volume, report readiness, and operator review status."
        icon={Search}
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label="Investigations"
          value={String(investigations.length)}
          detail={`${runningCount} running workflow${runningCount === 1 ? "" : "s"}`}
          icon={Search}
        />
        <MetricCard label="Targets" value={String(targets.length)} detail="Domains, emails, and entities queued" icon={Target} />
        <MetricCard
          label="Findings"
          value={String(findings.length)}
          detail={`${highRiskCount} high-priority item${highRiskCount === 1 ? "" : "s"}`}
          icon={Flag}
        />
        <MetricCard label="Reports" value={String(reports.length)} detail="Rendered exports and briefings" icon={FileText} />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1fr_420px]">
        <section className="rounded-md border border-zinc-800 bg-zinc-900/70">
          <div className="flex items-center justify-between border-b border-zinc-800 px-4 py-3">
            <h2 className="text-sm font-semibold text-zinc-100">Recent findings</h2>
            <AlertTriangle className="size-4 text-amber-200" aria-hidden="true" />
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] text-left text-sm">
              <thead className="text-xs uppercase text-zinc-500">
                <tr className="border-b border-zinc-800">
                  <th className="px-4 py-3 font-medium">Source</th>
                  <th className="px-4 py-3 font-medium">Severity</th>
                  <th className="px-4 py-3 font-medium">Confidence</th>
                  <th className="px-4 py-3 font-medium">Finding</th>
                  <th className="px-4 py-3 font-medium">Updated</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800">
                {latestFindings.map((finding) => (
                  <tr key={finding.id}>
                    <td className="px-4 py-3 font-medium text-zinc-100">{finding.source}</td>
                    <td className="px-4 py-3"><StatusPill value={finding.severity} /></td>
                    <td className="px-4 py-3 font-mono text-zinc-300">{formatPercent(finding.confidence)}</td>
                    <td className="px-4 py-3 text-zinc-400">{String(finding.data.value ?? "No summary")}</td>
                    <td className="px-4 py-3 text-zinc-500">{formatDate(finding.updated_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <LiveTimeline initialEvents={getTimelineEvents()} />
      </div>
    </>
  );
}
