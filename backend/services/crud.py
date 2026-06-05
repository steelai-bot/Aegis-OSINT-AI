"""CRUD services for Aegis v2 domain models."""

from __future__ import annotations

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
    ) -> Finding:
        finding = Finding(
            investigation_id=investigation_id,
            target_id=target_id,
            source=source,
            confidence=confidence,
            severity=severity,
            data=data,
        )
        self.session.add(finding)
        await self.session.commit()
        await self.session.refresh(finding)
        return finding

    async def list_findings(self, investigation_id: UUID | None = None) -> list[Finding]:
        statement = select(Finding).order_by(Finding.created_at.desc())
        if investigation_id is not None:
            statement = statement.where(Finding.investigation_id == investigation_id)
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
