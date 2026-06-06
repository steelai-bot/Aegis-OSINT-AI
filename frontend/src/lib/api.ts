import * as sample from "./sample-data";
import type {
  CollectionRunQueuedResponse,
  CollectionRunStatus,
  Finding,
  Investigation,
  PluginStatus,
  Report,
  Target,
  TimelineEvent,
} from "./types";

const apiBaseUrl = process.env.NEXT_PUBLIC_AEGIS_API_URL;

type CollectionWorkflowPayload = {
  plugin_name?: string;
  priority?: number;
  config?: Record<string, unknown>;
  enrich?: boolean;
  async_mode: true;
};

export function isApiConfigured(): boolean {
  return Boolean(apiBaseUrl);
}

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

async function postJson<T>(path: string, body: unknown): Promise<T> {
  if (!apiBaseUrl) {
    throw new Error("Backend API URL is not configured.");
  }

  const response = await fetch(`${apiBaseUrl.replace(/\/$/, "")}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new Error(`Backend API request failed with status ${response.status}.`);
  }

  return (await response.json()) as T;
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

export async function queueTargetCollection(
  targetId: string,
  payload: CollectionWorkflowPayload = { async_mode: true },
): Promise<CollectionRunQueuedResponse> {
  return postJson(`/api/v1/targets/${targetId}/collect`, { ...payload, async_mode: true });
}

export async function queueInvestigationCollection(
  investigationId: string,
  payload: CollectionWorkflowPayload = { async_mode: true },
): Promise<CollectionRunQueuedResponse> {
  return postJson(`/api/v1/investigations/${investigationId}/collect`, { ...payload, async_mode: true });
}

export async function getCollectionRunStatus(runId: string): Promise<CollectionRunStatus> {
  if (!apiBaseUrl) {
    throw new Error("Backend API URL is not configured.");
  }

  const response = await fetch(`${apiBaseUrl.replace(/\/$/, "")}/api/v1/collections/runs/${runId}`, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Collection run status request failed with status ${response.status}.`);
  }

  return (await response.json()) as CollectionRunStatus;
}
