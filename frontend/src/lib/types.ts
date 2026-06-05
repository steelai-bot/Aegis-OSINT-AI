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
