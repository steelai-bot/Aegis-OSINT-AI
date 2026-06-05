"""Plugin registry and configuration contract tests."""

import pytest

import backend.plugins.hibp as hibp_module
import backend.plugins.securitytrails as securitytrails_module
import backend.plugins.shodan as shodan_module
import backend.plugins.virustotal as virustotal_module
from backend.core.config import Settings
from backend.plugins.base import BasePlugin, PluginResult
from backend.plugins.hibp import HaveIBeenPwnedPlugin
from backend.plugins.registry import PluginRegistry
from backend.plugins.securitytrails import SecurityTrailsPlugin
from backend.plugins.shodan import ShodanPlugin
from backend.plugins.virustotal import VirusTotalPlugin


class EnabledPlugin(BasePlugin):
    name = "enabled"

    async def execute(self, target: str, context: dict | None = None) -> PluginResult:
        return PluginResult(plugin_name=self.name, status="completed", metadata={"config": self.config})


class DisabledByDefaultPlugin(BasePlugin):
    name = "disabled_by_default"
    enabled = False

    async def execute(self, target: str, context: dict | None = None) -> PluginResult:
        return PluginResult(plugin_name=self.name, status="completed")


class OtherPlugin(BasePlugin):
    name = "other"

    async def execute(self, target: str, context: dict | None = None) -> PluginResult:
        return PluginResult(plugin_name=self.name, status="completed")


def test_plugin_registry_filters_and_injects_plugin_config() -> None:
    registry = PluginRegistry(
        [EnabledPlugin, DisabledByDefaultPlugin, OtherPlugin],
        enabled_plugin_names=["enabled", "disabled_by_default"],
        disabled_plugin_names=["other"],
        plugin_configs={"enabled": {"timeout": 5}},
    )

    plugins = registry.enabled_plugins()

    assert [plugin.name for plugin in plugins] == ["enabled"]
    assert plugins[0].config == {"timeout": 5}
    assert registry.is_enabled(EnabledPlugin)
    assert not registry.is_enabled(DisabledByDefaultPlugin)
    assert not registry.is_enabled(OtherPlugin)


@pytest.mark.parametrize(
    ("plugin_class", "module"),
    [
        (ShodanPlugin, shodan_module),
        (VirusTotalPlugin, virustotal_module),
        (SecurityTrailsPlugin, securitytrails_module),
        (HaveIBeenPwnedPlugin, hibp_module),
    ],
)
@pytest.mark.asyncio
async def test_api_backed_plugins_skip_without_required_api_keys(monkeypatch, plugin_class, module) -> None:
    monkeypatch.setattr(module, "get_settings", lambda: Settings())

    result = await plugin_class().execute("example.com")

    assert result.status == "skipped"
    assert result.metadata == {"reason": "missing_api_key"}
    assert result.findings == []
