"""Risk scoring for passive threat intelligence findings."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


SEVERITY_WEIGHTS = {
    "critical": 25.0,
    "high": 20.0,
    "medium": 12.0,
    "low": 6.0,
    "info": 2.0,
}

THREAT_CATEGORY_WEIGHTS = {
    "credential_leak": 25.0,
    "cloud_exposure": 22.0,
    "phishing": 20.0,
    "darkweb_mention": 16.0,
    "brand_impersonation": 14.0,
    "domain_monitoring": 10.0,
}


class RiskScoringService:
    """Calculate bounded 0-100 risk scores without external side effects."""

    def score(self, finding: dict[str, Any]) -> float:
        score = 0.0
        score += THREAT_CATEGORY_WEIGHTS.get(str(finding.get("threat_category", "unknown")), 4.0)
        score += SEVERITY_WEIGHTS.get(str(finding.get("severity", "info")), 2.0)
        score += self._confidence_score(finding.get("confidence", 0.0))
        score += self._freshness_score(finding.get("first_seen") or finding.get("breach_date"))
        score += self._actor_score(finding)
        return round(min(max(score, 0.0), 100.0), 2)

    def exploitability(self, score: float) -> str:
        if score >= 85:
            return "critical"
        if score >= 70:
            return "high"
        if score >= 40:
            return "medium"
        if score > 0:
            return "low"
        return "unknown"

    def apply(self, finding: dict[str, Any]) -> dict[str, Any]:
        scored = dict(finding)
        score = self.score(scored)
        scored["risk_score"] = score
        scored["exploitability"] = self.exploitability(score)
        return scored

    def _confidence_score(self, confidence: Any) -> float:
        try:
            return min(max(float(confidence), 0.0), 1.0) * 20.0
        except (TypeError, ValueError):
            return 0.0

    def _freshness_score(self, value: Any) -> float:
        observed_at = self._parse_datetime(value)
        if observed_at is None:
            return 4.0
        age_days = max((datetime.now(UTC) - observed_at).days, 0)
        if age_days <= 1:
            return 20.0
        if age_days <= 7:
            return 16.0
        if age_days <= 30:
            return 12.0
        if age_days <= 180:
            return 6.0
        return 2.0

    def _actor_score(self, finding: dict[str, Any]) -> float:
        if finding.get("threat_actor"):
            return 10.0
        if finding.get("campaign_id"):
            return 6.0
        return 0.0

    def _parse_datetime(self, value: Any) -> datetime | None:
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=UTC)
        if isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
            except ValueError:
                return None
        return None