"""DNS OSINT plugin."""

from typing import Any

from backend.plugins.base import BasePlugin, PluginResult


class DnsPlugin(BasePlugin):
    name = "dns"
    record_types = ("A", "AAAA", "MX", "NS", "TXT")

    async def execute(self, target: str, context: dict[str, Any] | None = None) -> PluginResult:
        import dns.asyncresolver

        findings: list[dict[str, Any]] = []
        resolver = dns.asyncresolver.Resolver()
        for record_type in self.record_types:
            try:
                answers = await resolver.resolve(target, record_type)
            except dns.exception.DNSException:
                continue
            for answer in answers:
                findings.append(
                    {
                        "source": self.name,
                        "type": f"dns.{record_type.lower()}",
                        "value": str(answer).strip(),
                        "confidence": 0.9,
                        "data": {"record_type": record_type, "domain": target},
                    }
                )
        return PluginResult(plugin_name=self.name, status="completed", findings=findings)
