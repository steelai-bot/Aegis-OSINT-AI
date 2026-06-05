"use client";

import { Radio } from "lucide-react";
import { useEffect, useState } from "react";

import { formatDate } from "@/lib/format";
import type { TimelineEvent } from "@/lib/types";

type ConnectionState = "connecting" | "live" | "fallback";

export function LiveTimeline({ initialEvents }: { initialEvents: TimelineEvent[] }) {
  const [events, setEvents] = useState<TimelineEvent[]>(initialEvents);
  const websocketUrl = process.env.NEXT_PUBLIC_AEGIS_WS_URL;
  const [connectionState, setConnectionState] = useState<ConnectionState>(websocketUrl ? "connecting" : "fallback");

  useEffect(() => {
    if (!websocketUrl) {
      return;
    }

    const socket = new WebSocket(websocketUrl);

    socket.addEventListener("open", () => setConnectionState("live"));
    socket.addEventListener("message", (message) => {
      try {
        const event = JSON.parse(message.data) as TimelineEvent;
        setEvents((current) => [event, ...current].slice(0, 12));
      } catch {
        setConnectionState("fallback");
      }
    });
    socket.addEventListener("error", () => setConnectionState("fallback"));

    return () => socket.close();
  }, [websocketUrl]);

  useEffect(() => {
    if (connectionState !== "fallback") {
      return;
    }

    const interval = window.setInterval(() => {
      const nextEvent: TimelineEvent = {
        id: `local-${Date.now()}`,
        type: "workflow.heartbeat",
        title: "Local timeline heartbeat",
        detail: "Waiting for NEXT_PUBLIC_AEGIS_WS_URL; showing deterministic local stream.",
        timestamp: new Date().toISOString(),
        severity: "info",
      };
      setEvents((current) => [nextEvent, ...current].slice(0, 8));
    }, 8000);

    return () => window.clearInterval(interval);
  }, [connectionState]);

  return (
    <section className="rounded-md border border-zinc-800 bg-zinc-900/70">
      <div className="flex items-center justify-between gap-3 border-b border-zinc-800 px-4 py-3">
        <div className="flex items-center gap-2">
          <Radio className="size-4 text-cyan-200" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-zinc-100">Live timeline</h2>
        </div>
        <span className="text-xs font-medium text-zinc-500">{connectionState}</span>
      </div>
      <ol className="divide-y divide-zinc-800">
        {events.map((event) => (
          <li key={event.id} className="grid gap-2 px-4 py-3 sm:grid-cols-[140px_1fr]">
            <time className="text-xs font-medium text-zinc-500">{formatDate(event.timestamp)}</time>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <p className="text-sm font-medium text-zinc-100">{event.title}</p>
                <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400">{event.type}</span>
              </div>
              <p className="mt-1 text-sm leading-5 text-zinc-400">{event.detail}</p>
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}
