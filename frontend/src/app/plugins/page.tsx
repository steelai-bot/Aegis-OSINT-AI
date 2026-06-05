import { Plug } from "lucide-react";

import { PageHeader } from "@/components/page-header";
import { StatusPill } from "@/components/status-pill";
import { getPlugins } from "@/lib/api";

export default function PluginsPage() {
  const plugins = getPlugins();

  return (
    <>
      <PageHeader
        title="Plugins"
        description="Inspect passive enrichment coverage and identify providers that need API credentials."
        icon={Plug}
      />

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {plugins.map((plugin) => (
          <article key={plugin.name} className="rounded-md border border-zinc-800 bg-zinc-900/70 p-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold text-zinc-100">{plugin.name}</h2>
                <p className="mt-1 text-xs uppercase text-zinc-500">{plugin.category}</p>
              </div>
              <StatusPill value={plugin.status} />
            </div>
            <p className="mt-4 text-sm leading-6 text-zinc-400">{plugin.coverage}</p>
          </article>
        ))}
      </section>
    </>
  );
}
