"""Passive collection orchestration for EASM and threat intelligence plugins."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.events import EventBus, event_bus
from backend.plugins.base import BasePlugin, PluginResult
from backend.plugins.registry import PluginRegistry
from backend.services.crud import FindingService
from backend.services.egress_audit import EgressAuditSubscriber
from backend.services.enrichment_pipeline import EnrichmentPipeline
from backend.services.risk_scoring import RiskScoringService
from backend.services.tool_execution import ToolExecutionController


@dataclass(frozen=True, slots=True)
class CollectionJob:
    """Explicit passive collection job definition."""

    target: str
    target_type: str
    plugin_name: str | None = None
    investigation_id: UUID | None = None
    target_id: UUID | None = None
    priority: int = 100
    config: dict[str, Any] = field(default_factory=dict)
    enrich: bool = False
    execution_mode: str | None = None
    approval_token: str | None = None
    authorized_scope: str | None = None


@dataclass(slots=True)
class CollectionRunResult:
    """Normalized collection run summary."""

    target: str
    plugin_results: list[PluginResult] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    persisted_count: int = 0
    errors: dict[str, str] = field(default_factory=dict)


class CollectionOrchestrator:
    """Run approved passive collectors and persist normalized findings."""

    def __init__(
        self,
        *,
        registry: PluginRegistry | None = None,
        session: AsyncSession | None = None,
        bus: EventBus | None = None,
        scorer: RiskScoringService | None = None,
        enrichment: EnrichmentPipeline | None = None,
        tool_execution: ToolExecutionController | None = None,
    ) -> None:
        self.registry = registry or PluginRegistry()
        self.session = session
        self.event_bus = bus or (EventBus() if session is not None else event_bus)
        self.scorer = scorer or RiskScoringService()
        self.enrichment = enrichment or EnrichmentPipeline(registry=self.registry, scorer=self.scorer)
        self.tool_execution = tool_execution or ToolExecutionController(audit_session=session)

    async def run_job(self, job: CollectionJob) -> CollectionRunResult:
        egress_audit = EgressAuditSubscriber(self.session) if self.session is not None else None
        if egress_audit is not None:
            egress_audit.subscribe(self.event_bus)

        await self.event_bus.publish(
            "collection.started",
            {"target": job.target, "target_type": job.target_type, "plugin_name": job.plugin_name, "priority": job.priority},
        )

        try:
            run_result = CollectionRunResult(target=job.target)
            for plugin in self._plugins_for_job(job):
                plugin.event_bus = self.event_bus
                decision = await self.tool_execution.authorize(
                    plugin=plugin,
                    target=job.target,
                    target_type=job.target_type,
                    requested_mode=job.execution_mode,
                    approval_token=job.approval_token,
                    authorized_scope=job.authorized_scope,
                )
                await self.tool_execution.record_decision(decision)
                await self.event_bus.publish(
                    "tool.execution.decision",
                    {"plugin_name": plugin.name, "status": decision.status, "reason": decision.reason},
                )

                if not decision.allowed:
                    run_result.plugin_results.append(
                        PluginResult(plugin_name=plugin.name, status=decision.status, metadata=decision.plugin_result_metadata())
                    )
                    continue

                try:
                    plugin_result = await plugin.execute(job.target, context={"target_type": job.target_type, "job_config": job.config})
                except Exception as exc:  # Defensive boundary around untrusted external providers.
                    run_result.errors[plugin.name] = str(exc)
                    await self.tool_execution.record_outcome(decision=decision, status="error", error=str(exc))
                    await self.event_bus.publish(
                        "tool.execution.failed",
                        {"plugin_name": plugin.name, "status": "error", "error": str(exc)},
                    )
                    continue

                await self.tool_execution.record_outcome(
                    decision=decision,
                    status=plugin_result.status,
                    finding_count=len(plugin_result.findings),
                )
                await self.event_bus.publish(
                    "tool.execution.completed",
                    {"plugin_name": plugin.name, "status": plugin_result.status, "finding_count": len(plugin_result.findings)},
                )
                run_result.plugin_results.append(plugin_result)
                normalized = [self.normalize_finding(raw, plugin=plugin, job=job) for raw in plugin_result.findings]
                if job.enrich:
                    normalized = [await self.enrichment.enrich(finding) for finding in normalized]
                else:
                    normalized = [self.scorer.apply(finding) for finding in normalized]
                run_result.findings.extend(normalized)

            run_result.findings = self.deduplicate(run_result.findings)
            if self.session is not None and job.investigation_id is not None:
                run_result.persisted_count = await self.persist_findings(run_result.findings, job=job)

            await self.event_bus.publish(
                "collection.completed",
                {
                    "target": job.target,
                    "target_type": job.target_type,
                    "finding_count": len(run_result.findings),
                    "persisted_count": run_result.persisted_count,
                    "errors": run_result.errors,
                },
            )
            return run_result
        finally:
            if egress_audit is not None:
                egress_audit.unsubscribe(self.event_bus)

    def normalize_finding(self, raw: dict[str, Any], *, plugin: BasePlugin, job: CollectionJob) -> dict[str, Any]:
        now = datetime.now(UTC)
        data = dict(raw.get("data") or {})
        data.setdefault("target", job.target)
        return {
            "source": raw.get("source") or plugin.name,
            "type": raw.get("type"),
            "value": raw.get("value") or job.target,
            "confidence": float(raw.get("confidence", 0.0)),
            "severity": raw.get("severity", "info"),
            "data": data,
            "threat_category": raw.get("threat_category") or plugin.threat_category,
            "indicator_type": raw.get("indicator_type") or self._default_indicator_type(plugin, job),
            "first_seen": raw.get("first_seen") or now,
            "last_seen": raw.get("last_seen") or now,
            "breach_date": raw.get("breach_date"),
            "threat_actor": raw.get("threat_actor"),
            "campaign_id": raw.get("campaign_id"),
            "source_url": raw.get("source_url"),
            "collector_plugin": raw.get("collector_plugin") or plugin.name,
            "raw_evidence": raw.get("raw_evidence") or raw,
            "enriched": bool(raw.get("enriched", False)),
            "enrichment_data": raw.get("enrichment_data") or {},
            "risk_score": float(raw.get("risk_score", 0.0)),
            "exploitability": raw.get("exploitability", "unknown"),
            "remediation_status": raw.get("remediation_status", "open"),
            "remediation_notes": raw.get("remediation_notes"),
        }

    def deduplicate(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        for finding in findings:
            key = self._dedup_key(finding)
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        return unique

    async def persist_findings(self, findings: list[dict[str, Any]], *, job: CollectionJob) -> int:
        if self.session is None or job.investigation_id is None:
            return 0
        service = FindingService(self.session)
        count = 0
        for finding in findings:
            saved = await service.create_finding(
                investigation_id=job.investigation_id,
                target_id=job.target_id,
                source=str(finding["source"]),
                confidence=float(finding["confidence"]),
                severity=str(finding["severity"]),
                data=dict(finding.get("data") or {}),
                threat_category=str(finding["threat_category"]),
                indicator_type=str(finding["indicator_type"]),
                first_seen=finding.get("first_seen"),
                last_seen=finding.get("last_seen"),
                breach_date=finding.get("breach_date"),
                threat_actor=finding.get("threat_actor"),
                campaign_id=finding.get("campaign_id"),
                source_url=finding.get("source_url"),
                collector_plugin=str(finding.get("collector_plugin") or ""),
                raw_evidence=dict(finding.get("raw_evidence") or {}),
                enriched=bool(finding.get("enriched", False)),
                enrichment_data=dict(finding.get("enrichment_data") or {}),
                risk_score=float(finding.get("risk_score", 0.0)),
                exploitability=str(finding.get("exploitability", "unknown")),
                remediation_status=str(finding.get("remediation_status", "open")),
                remediation_notes=finding.get("remediation_notes"),
            )
            count += 1
            await self.event_bus.publish(
                "finding.created",
                {"finding_id": str(saved.id), "source": saved.source, "threat_category": saved.threat_category},
            )
        return count

    def _plugins_for_job(self, job: CollectionJob) -> list[BasePlugin]:
        plugins = self.registry.enabled_plugins()
        if job.plugin_name is None:
            return [plugin for plugin in plugins if self._plugin_supports_job(plugin, job)]
        return [plugin for plugin in plugins if plugin.name == job.plugin_name and self._plugin_supports_job(plugin, job)]

    def _plugin_supports_job(self, plugin: BasePlugin, job: CollectionJob) -> bool:
        if not plugin.indicator_types:
            return job.plugin_name == plugin.name
        if job.target_type in plugin.indicator_types:
            return True
        return job.target_type == "brand" and "keyword" in plugin.indicator_types

    def _default_indicator_type(self, plugin: BasePlugin, job: CollectionJob) -> str:
        if plugin.indicator_types:
            return plugin.indicator_types[0]
        return job.target_type or "unknown"

    def _dedup_key(self, finding: dict[str, Any]) -> str:
        value = "|".join(
            str(finding.get(key, "")) for key in ("collector_plugin", "threat_category", "indicator_type", "value", "source_url")
        )
        return sha256(value.encode("utf-8", errors="ignore")).hexdigest()