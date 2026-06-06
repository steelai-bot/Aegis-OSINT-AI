"""CRUD services for Aegis v2 domain models."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.finding import Finding
from backend.models.investigation import Investigation
from backend.models.report import Report
from backend.models.target import Target


class InvestigationService:
    """Persistence operations for investigation records."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create_investigation(self, title: str) -> Investigation:
        investigation = Investigation(title=title, status="pending")
        self.session.add(investigation)
        await self.session.commit()
        await self.session.refresh(investigation)
        return investigation

    async def list_investigations(self) -> list[Investigation]:
        result = await self.session.execute(select(Investigation).order_by(Investigation.created_at.desc()))
        return list(result.scalars().all())

    async def get_investigation(self, investigation_id: UUID) -> Investigation | None:
        return await self.session.get(Investigation, investigation_id)


class TargetService:
    """Persistence operations for target records."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create_target(self, investigation_id: UUID, target_type: str, value: str) -> Target:
        target = Target(investigation_id=investigation_id, type=target_type, value=value)
        self.session.add(target)
        await self.session.commit()
        await self.session.refresh(target)
        return target

    async def list_targets(self, investigation_id: UUID) -> list[Target]:
        result = await self.session.execute(
            select(Target).where(Target.investigation_id == investigation_id).order_by(Target.created_at.desc())
        )
        return list(result.scalars().all())

    async def get_target(self, target_id: UUID) -> Target | None:
        return await self.session.get(Target, target_id)


class FindingService:
    """Persistence operations for normalized findings."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create_finding(
        self,
        investigation_id: UUID,
        source: str,
        confidence: float,
        severity: str,
        data: dict,
        target_id: UUID | None = None,
        threat_category: str = "unknown",
        indicator_type: str = "unknown",
        first_seen: datetime | None = None,
        last_seen: datetime | None = None,
        breach_date: datetime | None = None,
        threat_actor: str | None = None,
        campaign_id: str | None = None,
        source_url: str | None = None,
        collector_plugin: str = "",
        raw_evidence: dict | None = None,
        enriched: bool = False,
        enrichment_data: dict | None = None,
        risk_score: float = 0.0,
        exploitability: str = "unknown",
        remediation_status: str = "open",
        remediation_notes: str | None = None,
    ) -> Finding:
        now = datetime.now(UTC)
        finding = Finding(
            investigation_id=investigation_id,
            target_id=target_id,
            source=source,
            confidence=confidence,
            severity=severity,
            data=data,
            threat_category=threat_category,
            indicator_type=indicator_type,
            first_seen=first_seen or now,
            last_seen=last_seen or first_seen or now,
            breach_date=breach_date,
            threat_actor=threat_actor,
            campaign_id=campaign_id,
            source_url=source_url,
            collector_plugin=collector_plugin,
            raw_evidence=raw_evidence or {},
            enriched=enriched,
            enrichment_data=enrichment_data or {},
            risk_score=risk_score,
            exploitability=exploitability,
            remediation_status=remediation_status,
            remediation_notes=remediation_notes,
        )
        self.session.add(finding)
        await self.session.commit()
        await self.session.refresh(finding)
        return finding

    async def list_findings(
        self,
        investigation_id: UUID | None = None,
        threat_category: str | None = None,
        indicator_type: str | None = None,
        severity: str | None = None,
        remediation_status: str | None = None,
    ) -> list[Finding]:
        statement = select(Finding).order_by(Finding.created_at.desc())
        if investigation_id is not None:
            statement = statement.where(Finding.investigation_id == investigation_id)
        if threat_category is not None:
            statement = statement.where(Finding.threat_category == threat_category)
        if indicator_type is not None:
            statement = statement.where(Finding.indicator_type == indicator_type)
        if severity is not None:
            statement = statement.where(Finding.severity == severity)
        if remediation_status is not None:
            statement = statement.where(Finding.remediation_status == remediation_status)
        result = await self.session.execute(statement)
        return list(result.scalars().all())


class ReportService:
    """Persistence operations for generated reports."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create_report(self, investigation_id: UUID, path: str, report_format: str) -> Report:
        report = Report(investigation_id=investigation_id, path=path, format=report_format)
        self.session.add(report)
        await self.session.commit()
        await self.session.refresh(report)
        return report

    async def list_reports(self, investigation_id: UUID | None = None) -> list[Report]:
        statement = select(Report).order_by(Report.created_at.desc())
        if investigation_id is not None:
            statement = statement.where(Report.investigation_id == investigation_id)
        result = await self.session.execute(statement)
        return list(result.scalars().all())
