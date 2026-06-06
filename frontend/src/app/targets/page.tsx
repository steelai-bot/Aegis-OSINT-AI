import { Plus, Target as TargetIcon } from "lucide-react";

import { CollectionRunControl } from "@/components/collection-run-control";
import { PageHeader } from "@/components/page-header";
import { formatDate } from "@/lib/format";
import { getInvestigationsWithSource, getTargetsWithSource } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function TargetsPage() {
  const investigations = await getInvestigationsWithSource();
  const targets = await getTargetsWithSource(investigations);
  const investigationTitles = new Map(investigations.data.map((investigation) => [investigation.id, investigation.title]));
  const collectionDisabledReason = targets.source === "live" ? undefined : "Sample data: live collection disabled";

  return (
    <>
      <PageHeader
        title="Targets"
        description="Manage approved OSINT targets and keep each entity tied to an investigation context."
        icon={TargetIcon}
        action={
          <button className="inline-flex h-10 items-center gap-2 rounded-md bg-cyan-300 px-3 text-sm font-semibold text-zinc-950 hover:bg-cyan-200">
            <Plus className="size-4" aria-hidden="true" />
            Add target
          </button>
        }
      />

      <section className="rounded-md border border-zinc-800 bg-zinc-900/70">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[960px] text-left text-sm">
            <thead className="text-xs uppercase text-zinc-500">
              <tr className="border-b border-zinc-800">
                <th className="px-4 py-3 font-medium">Value</th>
                <th className="px-4 py-3 font-medium">Type</th>
                <th className="px-4 py-3 font-medium">Investigation</th>
                <th className="px-4 py-3 font-medium">Created</th>
                <th className="px-4 py-3 font-medium">Collection</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {targets.data.map((target) => (
                <tr key={target.id}>
                  <td className="px-4 py-3 font-mono text-zinc-100">{target.value}</td>
                  <td className="px-4 py-3 text-zinc-300">{target.type}</td>
                  <td className="px-4 py-3 text-zinc-400">{investigationTitles.get(target.investigation_id) ?? "Unknown"}</td>
                  <td className="px-4 py-3 text-zinc-500">{formatDate(target.created_at)}</td>
                  <td className="px-4 py-3 align-top">
                    <CollectionRunControl scope="target" entityId={target.id} disabledReason={collectionDisabledReason} />
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
