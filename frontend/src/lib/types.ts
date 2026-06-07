export type InvestigationStatus = "queued" | "running" | "completed" | "failed";

export type Investigation = {
  id: string;
  title: string;
  status: InvestigationStatus;
  created_at: string;
  updated_at: string;
};

export type Target = {
  id: string;
  investigation_id: string;
  type: string;
  value: string;
  created_at: string;
  updated_at: string;
};

export type Finding = {
  id: string;
  investigation_id: string;
  target_id: string | null;
  source: string;
  confidence: number;
  severity: "info" | "low" | "medium" | "high" | "critical";
  data: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type Report = {
  id: string;
  investigation_id: string;
  path: string;
  format: "html" | "json" | "csv" | "markdown" | "briefing" | "pdf";
  created_at: string;
  updated_at: string;
};

export type TimelineEvent = {
  id: string;
  type: string;
  title: string;
  detail: string;
  timestamp: string;
  severity?: Finding["severity"];
};

export type PluginStatus = {
  name: string;
  category: string;
  status: "enabled" | "disabled" | "needs_key";
  coverage: string;
};

export type CollectionRunStatusValue = "queued" | "running" | "completed" | "failed";

export type CollectionRunQueuedResponse = {
  run_id: string;
  status: CollectionRunStatusValue;
  status_url: string;
};

export type ToolExecutionMode = "passive" | "operator_assisted" | "manual_review_only" | "disabled";

export type CollectionWorkflowPayload = {
  plugin_name?: string;
  priority?: number;
  config?: Record<string, unknown>;
  enrich?: boolean;
  async_mode: true;
  execution_mode?: Exclude<ToolExecutionMode, "disabled">;
  approval_token?: string;
  authorized_scope?: string;
};

export type CollectionRunStatus = {
  run_id: string;
  run_scope: "ad_hoc" | "target" | "investigation" | string;
  status: CollectionRunStatusValue;
  target: string | null;
  target_type: string | null;
  target_id: string | null;
  investigation_id: string | null;
  plugin_name: string | null;
  priority: number;
  enrich: boolean;
  persisted_count: number;
  result: Record<string, unknown>;
  errors: Record<string, unknown>;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
};

export type ToolExecutionApproval = {
  id: string;
  status: "active" | "used" | "revoked" | "expired" | string;
  plugin_name: string | null;
  target_type: string | null;
  target_hash: string | null;
  execution_mode: "operator_assisted" | "manual_review_only" | string;
  authorized_scope: string | null;
  reason: string | null;
  requested_by: string | null;
  approved_by: string | null;
  expires_at: string;
  used_at: string | null;
  revoked_at: string | null;
  max_uses: number;
  use_count: number;
  metadata_json: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type ToolExecutionApprovalCreatePayload = {
  plugin_name?: string;
  target_type?: string;
  target?: string;
  target_hash?: string;
  execution_mode: Extract<ToolExecutionMode, "operator_assisted" | "manual_review_only">;
  authorized_scope?: string;
  reason?: string;
  requested_by?: string;
  expires_in_minutes: number;
  max_uses: number;
  metadata?: Record<string, unknown>;
};

export type ToolExecutionApprovalCreated = ToolExecutionApproval & {
  approval_token: string;
};

export type ToolExecutionApprovalListResponse = {
  approvals: ToolExecutionApproval[];
};

export type AuditEvent = {
  id: string;
  event_type: string;
  actor_id: string | null;
  actor_role: string | null;
  resource_type: string | null;
  resource_id: string | null;
  status: string;
  request_id: string | null;
  ip_address: string | null;
  user_agent: string | null;
  metadata_json: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type AuditEventListResponse = {
  events: AuditEvent[];
};
