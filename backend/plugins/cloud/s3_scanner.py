"""Passive S3 bucket exposure metadata plugin."""

from __future__ import annotations

from typing import Any

import httpx

from backend.core.config import get_settings
from backend.core.http import http_client
from backend.plugins.base import BasePlugin, PluginResult


class S3ScannerPlugin(BasePlugin):
    """Check common S3 bucket names for public metadata exposure."""

    name = "s3_scanner"
    threat_category = "cloud_exposure"
    indicator_types = ("domain", "url")
    egress_allowed_hosts = ("*.s3.amazonaws.com",)

    async def execute(self, target: str, context: dict[str, Any] | None = None) -> PluginResult:
        bucket_names = self._bucket_candidates(target)
        settings = get_settings()
        findings: list[dict[str, Any]] = []
        errors: dict[str, str] = {}
        async with http_client(settings, **self.http_policy_kwargs()) as client:
            for bucket in bucket_names:
                url = f"https://{bucket}.s3.amazonaws.com/"
                try:
                    response = await client.get(url)
                except httpx.HTTPStatusError as exc:
                    status_code = exc.response.status_code
                    if status_code in (403, 404):
                        continue
                    errors[bucket] = str(exc)
                    continue
                except httpx.HTTPError as exc:
                    errors[bucket] = str(exc)
                    continue

                findings.append(
                    {
                        "source": self.name,
                        "type": "cloud.s3_bucket",
                        "value": bucket,
                        "confidence": 0.8,
                        "severity": "high" if "<ListBucketResult" in response.text else "medium",
                        "threat_category": self.threat_category,
                        "indicator_type": "url",
                        "collector_plugin": self.name,
                        "source_url": url,
                        "data": {
                            "target": target,
                            "bucket": bucket,
                            "status_code": response.status_code,
                            "content_type": response.headers.get("content-type"),
                        },
                        "raw_evidence": {"headers": dict(response.headers), "content_preview": response.text[:500]},
                    }
                )
        return PluginResult(plugin_name=self.name, status="completed", findings=findings, metadata={"errors": errors})

    def _bucket_candidates(self, target: str) -> tuple[str, ...]:
        configured = self.config.get("bucket_names")
        if configured:
            return tuple(str(bucket).strip().lower() for bucket in configured if str(bucket).strip())
        domain = target.lower().strip().removeprefix("http://").removeprefix("https://").split("/")[0]
        base = domain.split(".")[0]
        candidates = {domain.replace(".", "-"), base, f"{base}-backup", f"{base}-assets", f"{base}-logs"}
        return tuple(sorted(candidate for candidate in candidates if candidate))