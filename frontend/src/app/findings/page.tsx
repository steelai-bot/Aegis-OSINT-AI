import { Flag } from "lucide-react";

import { PageHeader } from "@/components/page-header";
import { StatusPill } from "@/components/status-pill";
import { formatDate, formatPercent } from "@/lib/format";
import { getFindings, getTargets } from "@/lib/api";

export default async function FindingsPage() {
  const [findings, targets] = await Promise.all([getFindings(), getTargets()]);
  const targetValues = new Map(targets.map((target) => [target.id, target.value]));

  return (
    <>
      <PageHeader
        title="Findings"
        description="Review normalized findings from passive plugins before they are included in operator reports."
        icon={Flag}
      />

      <section className="rounded-md border border-zinc-800 bg-zinc-900/70">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[880px] text-left text-sm">
            <thead className="text-xs uppercase text-zinc-500">
              <tr className="border-b border-zinc-800">
                <th className="px-4 py-3 font-medium">Source</th>
                <th className="px-4 py-3 font-medium">Target</th>
                <th className="px-4 py-3 font-medium">Severity</th>
                <th className="px-4 py-3 font-medium">Confidence</th>
                <th className="px-4 py-3 font-medium">Summary</th>
                <th className="px-4 py-3 font-medium">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {findings.map((finding) => (
                <tr key={finding.id}>
                  <td className="px-4 py-3 font-medium text-zinc-100">{finding.source}</td>
                  <td className="px-4 py-3 font-mono text-zinc-300">
                    {finding.target_id ? targetValues.get(finding.target_id) ?? "Unknown" : "Investigation"}
                  </td>
                  <td className="px-4 py-3"><StatusPill value={finding.severity} /></td>
                  <td className="px-4 py-3 font-mono text-zinc-300">{formatPercent(finding.confidence)}</td>
                  <td className="px-4 py-3 text-zinc-400">{String(finding.data.value ?? finding.data.finding_type ?? "No summary")}</td>
                  <td className="px-4 py-3 text-zinc-500">{formatDate(finding.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
