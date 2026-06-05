import { Settings } from "lucide-react";

import { PageHeader } from "@/components/page-header";

export const dynamic = "force-dynamic";

const settings = [
  { label: "Backend API URL", value: process.env.NEXT_PUBLIC_AEGIS_API_URL ?? "sample data mode" },
  { label: "Timeline websocket", value: process.env.NEXT_PUBLIC_AEGIS_WS_URL ?? "fallback local stream" },
  { label: "Report formats", value: "markdown, html, json, briefing, pdf" },
  { label: "Collection posture", value: "passive, operator-reviewed" },
];

export default function SettingsPage() {
  return (
    <>
      <PageHeader
        title="Settings"
        description="Review frontend runtime configuration and operational defaults for local deployment."
        icon={Settings}
      />

      <section className="rounded-md border border-zinc-800 bg-zinc-900/70 p-4">
        <dl className="grid gap-4 md:grid-cols-2">
          {settings.map((item) => (
            <div key={item.label} className="rounded-md border border-zinc-800 bg-zinc-950 p-4">
              <dt className="text-xs font-medium uppercase text-zinc-500">{item.label}</dt>
              <dd className="mt-2 break-words font-mono text-sm text-zinc-200">{item.value}</dd>
            </div>
          ))}
        </dl>
      </section>
    </>
  );
}
