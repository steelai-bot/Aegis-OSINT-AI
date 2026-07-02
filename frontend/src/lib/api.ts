import * as sample from "./sample-data";
import type {
  CollectionRunQueuedResponse,
  CollectionRunListResponse,
  CollectionRunStatus,
  AuditEvent,
  AuditEventListResponse,
  CollectionWorkflowPayload,
  Finding,
  Investigation,
  PluginStatus,
  Report,
  Target,
  TimelineEvent,
  ToolExecutionApproval,
  ToolExecutionApprovalCreatePayload,
  ToolExecutionApprovalCreated,
  ToolExecutionApprovalListResponse,
} from "./types";

const apiBaseUrl = process.env.NEXT_PUBLIC_AEGIS_API_URL || "http://localhost:8000";

export type ApiDataSource = "live" | "sample";

export type ApiDataResult<T> = {
  data: T;
  source: ApiDataSource;
};

export function isApiConfigured(): boolean {
  return Boolean(apiBaseUrl);
}

async function fetchJson<T>(path: string, fallback: T): Promise<T> {
  return (await fetchJsonWithSource(path, fallback)).data;
}

async function fetchJsonWithSource<T>(path: string, fallback: T): Promise<ApiDataResult<T>> {
  if (!apiBaseUrl) {
    return { data: fallback, source: "sample" };
  }

  try {
    const response = await fetch(`${apiBaseUrl.replace(/\/$/, "")}${path}`, {
      cache: "no-store",
    });

    if (!response.ok) {
      return { data: fallback, source: "sample" };
    }

    return { data: (await response.json()) as T, source: "live" };
  } catch {
    return { data: fallback, source: "sample" };
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

async function deleteJson<T>(path: string): Promise<T> {
  if (!apiBaseUrl) {
    throw new Error("Backend API URL is not configured.");
  }

  const response = await fetch(`${apiBaseUrl.replace(/\/$/, "")}${path}`, {
    method: "DELETE",
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Backend API request failed with status ${response.status}.`);
  }

  return (await response.json()) as T;
}

export async function getInvestigations(): Promise<Investigation[]> {
  return fetchJson("/api/v1/investigations", sample.investigations);
}

export async function getInvestigationsWithSource(): Promise<ApiDataResult<Investigation[]>> {
  return fetchJsonWithSource("/api/v1/investigations", sample.investigations);
}

export async function getTargets(): Promise<Target[]> {
  return (await getTargetsWithSource()).data;
}

export async function getTargetsWithSource(
  investigationResult?: ApiDataResult<Investigation[]>,
): Promise<ApiDataResult<Target[]>> {
  const investigations = investigationResult ?? (await getInvestigationsWithSource());
  if (!apiBaseUrl) {
    return { data: sample.targets, source: "sample" };
  }

  if (investigations.source !== "live") {
    return { data: sample.targets, source: "sample" };
  }

  const targetGroups = await Promise.all(
    investigations.data.map((investigation) =>
      fetchJsonWithSource(`/api/v1/investigations/${investigation.id}/targets`, [] as Target[]),
    ),
  );

  if (targetGroups.some((group) => group.source !== "live")) {
    return { data: sample.targets, source: "sample" };
  }

  return { data: targetGroups.flatMap((group) => group.data), source: "live" };
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

export async function cancelCollectionRun(runId: string): Promise<CollectionRunStatus> {
  return postJson(`/api/v1/collections/runs/${runId}/cancel`, {});
}

export async function getEntityCollectionRuns(
  entityType: "target" | "investigation",
  entityId: string,
  limit = 10,
): Promise<CollectionRunStatus[]> {
  return fetchJson(`/api/v1/${entityType}s/${entityId}/collection-runs?limit=${encodeURIComponent(String(limit))}`, []);
}

export async function getEntityCollectionRunsWithSource(
  entityType: "target" | "investigation",
  entityId: string,
  limit = 10,
): Promise<ApiDataResult<CollectionRunStatus[]>> {
  return fetchJsonWithSource<CollectionRunListResponse>(
    `/api/v1/${entityType}s/${entityId}/collection-runs?limit=${encodeURIComponent(String(limit))}`,
    { runs: sample.collectionRuns },
  );
}

export async function getCollectionRunsWithSource(limit = 10): Promise<ApiDataResult<CollectionRunStatus[]>> {
  const response = await fetchJsonWithSource<CollectionRunListResponse>(
    `/api/v1/collections/runs?limit=${encodeURIComponent(String(limit))}`,
    { runs: sample.collectionRuns },
  );
  return { data: response.data.runs, source: response.source };
}

export async function getToolExecutionApprovalsWithSource(): Promise<ApiDataResult<ToolExecutionApproval[]>> {
  const response = await fetchJsonWithSource<ToolExecutionApprovalListResponse>(
    "/api/v1/tool-execution/approvals",
    { approvals: sample.toolExecutionApprovals },
  );
  return { data: response.data.approvals, source: response.source };
}

export async function createToolExecutionApproval(
  payload: ToolExecutionApprovalCreatePayload,
): Promise<ToolExecutionApprovalCreated> {
  return postJson("/api/v1/tool-execution/approvals", payload);
}

export async function revokeToolExecutionApproval(approvalId: string): Promise<ToolExecutionApproval> {
  return deleteJson(`/api/v1/tool-execution/approvals/${approvalId}`);
}

// ── Enrichment ─────────────────────────────────────────────────────────────

export async function enrichIndicator(indicator: string, indicatorType: string): Promise<{
  indicator: string;
  indicator_type: string;
  enriched: boolean;
  enrichment_data: Record<string, unknown>;
  risk_score: number | null;
} > {
  return postJson("/api/v1/enrichment/enrich", { indicator, indicator_type: indicatorType });
}

// ── Report export ──────────────────────────────────────────────────────────

export async function exportReportCSV(investigationId: string): Promise<string> {
  if (!apiBaseUrl) throw new Error("Backend API URL is not configured.");
  const response = await fetch(
    `${apiBaseUrl.replace(/\/$/, "")}/api/v1/reports/export/${investigationId}/csv`,
    { cache: "no-store" },
  );
  if (!response.ok) throw new Error(`Export failed with status ${response.status}`);
  return response.text();
}

export async function exportReportPDF(investigationId: string): Promise<string> {
  if (!apiBaseUrl) throw new Error("Backend API URL is not configured.");
  const response = await fetch(
    `${apiBaseUrl.replace(/\/$/, "")}/api/v1/reports/export/${investigationId}/pdf`,
    { cache: "no-store" },
  );
  if (!response.ok) throw new Error(`Export failed with status ${response.status}`);
  return response.text();
}

// ── Worker monitoring ──────────────────────────────────────────────────────

export type WorkerStatusResult = {
  status: {
    queue_backend: string;
    redis_url: string | null;
    job_timeout_seconds: number;
    max_retries: number;
    worker_count: number;
    queue_depth: number;
    active_jobs: number;
    failed_jobs: number;
    completed_jobs: number;
    status: string;
  };
  metrics: {
    total_jobs: number;
    successful_jobs: number;
    failed_jobs: number;
    avg_job_duration_seconds: number;
    active_workers: number;
    queue_health: string;
  };
};

export async function getWorkerStatusWithSource(): Promise<ApiDataResult<WorkerStatusResult>> {
  return fetchJsonWithSource<WorkerStatusResult>("/api/v1/workers/status", {
    status: {
      queue_backend: "in_process",
      redis_url: null,
      job_timeout_seconds: 600,
      max_retries: 3,
      worker_count: 1,
      queue_depth: 0,
      active_jobs: 0,
      failed_jobs: 0,
      completed_jobs: 0,
      status: "healthy",
    },
    metrics: {
      total_jobs: 0,
      successful_jobs: 0,
      failed_jobs: 0,
      avg_job_duration_seconds: 0,
      active_workers: 1,
      queue_health: "healthy",
    },
  });
}

export async function getToolAuditEventsWithSource(): Promise<ApiDataResult<AuditEvent[]>> {
  const response = await fetchJsonWithSource<AuditEventListResponse>(
    "/api/v1/audit/events?event_type_prefix=tool.execution.&limit=100",
    { events: sample.auditEvents },
  );
  return { data: response.data.events, source: response.source };
}
