import * as sample from "./sample-data";
import type { Finding, Investigation, PluginStatus, Report, Target, TimelineEvent } from "./types";

const apiBaseUrl = process.env.NEXT_PUBLIC_AEGIS_API_URL;

async function fetchJson<T>(path: string, fallback: T): Promise<T> {
  if (!apiBaseUrl) {
    return fallback;
  }

  try {
    const response = await fetch(`${apiBaseUrl.replace(/\/$/, "")}${path}`, {
      cache: "no-store",
    });

    if (!response.ok) {
      return fallback;
    }

    return (await response.json()) as T;
  } catch {
    return fallback;
  }
}

export async function getInvestigations(): Promise<Investigation[]> {
  return fetchJson("/api/v1/investigations", sample.investigations);
}

export async function getTargets(): Promise<Target[]> {
  const investigations = await getInvestigations();
  if (!apiBaseUrl) {
    return sample.targets;
  }

  const targetGroups = await Promise.all(
    investigations.map((investigation) =>
      fetchJson(`/api/v1/investigations/${investigation.id}/targets`, [] as Target[]),
    ),
  );

  return targetGroups.flat();
}

export async function getFindings(): Promise<Finding[]> {
  return fetchJson("/api/v1/findings", sample.findings);
}

export async function getReports(): Promise<Report[]> {
  return fetchJson("/api/v1/reports", sample.reports);
}

export function getTimelineEvents(): TimelineEvent[] {
  return sample.timelineEvents;
}

export function getPlugins(): PluginStatus[] {
  return sample.plugins;
}
