import { Plus, Search } from "lucide-react";

import { CollectionRunControl } from "@/components/collection-run-control";
import { PageHeader } from "@/components/page-header";
import { StatusPill } from "@/components/status-pill";
import { formatDate } from "@/lib/format";
import { getFindings, getInvestigations, getTargets } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function InvestigationsPage() {
  const [investigations, targets, findings] = await Promise.all([getInvestigations(), getTargets(), getFindings()]);

  return (
    <>
      <PageHeader
        title="Investigations"
        description="Create and review passive collection workflows before running agents against approved targets."
        icon={Search}
        action={
          <button className="inline-flex h-10 items-center gap-2 rounded-md bg-cyan-300 px-3 text-sm font-semibold text-zinc-950 hover:bg-cyan-200">
            <Plus className="size-4" aria-hidden="true" />
            New investigation
          </button>
        }
      />

      <section className="rounded-md border border-zinc-800 bg-zinc-900/70">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[980px] text-left text-sm">
            <thead className="text-xs uppercase text-zinc-500">
              <tr className="border-b border-zinc-800">
                <th className="px-4 py-3 font-medium">Title</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Targets</th>
                <th className="px-4 py-3 font-medium">Findings</th>
                <th className="px-4 py-3 font-medium">Updated</th>
                <th className="px-4 py-3 font-medium">Collection</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {investigations.map((investigation) => (
                <tr key={investigation.id}>
                  <td className="px-4 py-3">
                    <p className="font-medium text-zinc-100">{investigation.title}</p>
                    <p className="mt-1 font-mono text-xs text-zinc-500">{investigation.id}</p>
                  </td>
                  <td className="px-4 py-3"><StatusPill value={investigation.status} /></td>
                  <td className="px-4 py-3 text-zinc-300">
                    {targets.filter((target) => target.investigation_id === investigation.id).length}
                  </td>
                  <td className="px-4 py-3 text-zinc-300">
                    {findings.filter((finding) => finding.investigation_id === investigation.id).length}
                  </td>
                  <td className="px-4 py-3 text-zinc-500">{formatDate(investigation.updated_at)}</td>
                  <td className="px-4 py-3 align-top">
                    <CollectionRunControl scope="investigation" entityId={investigation.id} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
