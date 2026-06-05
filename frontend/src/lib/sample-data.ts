import type { Finding, Investigation, PluginStatus, Report, Target, TimelineEvent } from "./types";

export const investigations: Investigation[] = [
  {
    id: "8e5bf7ba-4fc2-42d3-b08e-0b7157199b67",
    title: "Sofia fintech exposure review",
    status: "running",
    created_at: "2026-06-05T08:15:00.000Z",
    updated_at: "2026-06-05T10:42:00.000Z",
  },
  {
    id: "f191ff34-7045-4045-93e5-792e2fd49732",
    title: "Supplier domain trust check",
    status: "completed",
    created_at: "2026-06-04T12:20:00.000Z",
    updated_at: "2026-06-04T14:11:00.000Z",
  },
  {
    id: "522f44f1-52f5-4ff9-ae8f-1a081e29ff23",
    title: "Executive footprint baseline",
    status: "queued",
    created_at: "2026-06-05T09:30:00.000Z",
    updated_at: "2026-06-05T09:30:00.000Z",
  },
];

export const targets: Target[] = [
  {
    id: "3dfda7a1-3c2b-4c92-8f6c-0b4d00c6fc88",
    investigation_id: investigations[0].id,
    type: "domain",
    value: "example-finance.bg",
    created_at: "2026-06-05T08:17:00.000Z",
    updated_at: "2026-06-05T08:17:00.000Z",
  },
  {
    id: "5e026f07-912c-4337-8c78-58fbc22f24f5",
    investigation_id: investigations[0].id,
    type: "email",
    value: "security@example-finance.bg",
    created_at: "2026-06-05T08:18:00.000Z",
    updated_at: "2026-06-05T08:18:00.000Z",
  },
  {
    id: "3a551713-5a39-4ce1-9ca7-a89b0eea8927",
    investigation_id: investigations[1].id,
    type: "domain",
    value: "supplier-network.eu",
    created_at: "2026-06-04T12:24:00.000Z",
    updated_at: "2026-06-04T12:24:00.000Z",
  },
];

export const findings: Finding[] = [
  {
    id: "b8b30f64-9e54-4494-a0d0-07539f358278",
    investigation_id: investigations[0].id,
    target_id: targets[0].id,
    source: "crt.sh",
    confidence: 0.91,
    severity: "medium",
    data: { finding_type: "certificate", hostname: "vpn.example-finance.bg", value: "recent certificate issuance" },
    created_at: "2026-06-05T08:49:00.000Z",
    updated_at: "2026-06-05T08:49:00.000Z",
  },
  {
    id: "a7057145-d519-40d9-844f-9ecb1212f808",
    investigation_id: investigations[0].id,
    target_id: targets[0].id,
    source: "dns",
    confidence: 0.84,
    severity: "low",
    data: { finding_type: "dns", host: "mail.example-finance.bg", value: "MX host observed" },
    created_at: "2026-06-05T09:12:00.000Z",
    updated_at: "2026-06-05T09:12:00.000Z",
  },
  {
    id: "e1d35daa-a7ad-4943-93df-afb9cb0cbb4f",
    investigation_id: investigations[1].id,
    target_id: targets[2].id,
    source: "securitytrails",
    confidence: 0.76,
    severity: "high",
    data: { finding_type: "exposure", ip: "203.0.113.42", value: "legacy service fingerprint" },
    created_at: "2026-06-04T13:06:00.000Z",
    updated_at: "2026-06-04T13:06:00.000Z",
  },
];

export const reports: Report[] = [
  {
    id: "5a875369-62a5-48f6-91cb-c7df2665120d",
    investigation_id: investigations[0].id,
    path: "reports/sofia-fintech-exposure.md",
    format: "markdown",
    created_at: "2026-06-05T10:30:00.000Z",
    updated_at: "2026-06-05T10:30:00.000Z",
  },
  {
    id: "05eda123-ad65-44a1-b367-f2d91d9d6588",
    investigation_id: investigations[1].id,
    path: "reports/supplier-domain-trust.pdf",
    format: "pdf",
    created_at: "2026-06-04T14:12:00.000Z",
    updated_at: "2026-06-04T14:12:00.000Z",
  },
];

export const timelineEvents: TimelineEvent[] = [
  {
    id: "evt-001",
    type: "workflow.started",
    title: "Investigation workflow started",
    detail: "Domain, breach, and report agents were queued for example-finance.bg.",
    timestamp: "2026-06-05T10:40:00.000Z",
  },
  {
    id: "evt-002",
    type: "finding.created",
    title: "Certificate finding created",
    detail: "crt.sh returned a new VPN hostname with medium confidence.",
    timestamp: "2026-06-05T10:41:00.000Z",
    severity: "medium",
  },
  {
    id: "evt-003",
    type: "workflow.step.completed",
    title: "DNS enrichment completed",
    detail: "DNS agent completed without contacting targets directly.",
    timestamp: "2026-06-05T10:42:00.000Z",
    severity: "low",
  },
];

export const plugins: PluginStatus[] = [
  { name: "WHOIS", category: "passive osint", status: "enabled", coverage: "registrar and ownership metadata" },
  { name: "DNS", category: "passive osint", status: "enabled", coverage: "records and host pivots" },
  { name: "crt.sh", category: "certificate intel", status: "enabled", coverage: "certificate transparency" },
  { name: "Shodan", category: "exposure intel", status: "needs_key", coverage: "internet-facing service metadata" },
  { name: "VirusTotal", category: "reputation", status: "needs_key", coverage: "domain and file reputation" },
  { name: "SecurityTrails", category: "asset intel", status: "needs_key", coverage: "historic DNS and subdomains" },
  { name: "HaveIBeenPwned", category: "breach intel", status: "needs_key", coverage: "breach exposure checks" },
];
