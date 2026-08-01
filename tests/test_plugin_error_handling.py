import asyncio

import pytest

from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugin_manager import PluginManager
from backend.plugins.base import BasePlugin, PluginExecutionError


class FakeSuccessPlugin(BasePlugin):
    def __init__(self):
        self.call_count = 0

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="fake_success",
            description="Always succeeds",
            supported_entity_types=[TargetType.DOMAIN],
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        self.call_count += 1
        return [
            PluginResponse(
                provider="fake_success",
                entity_type=target_type,
                confidence=0.9,
                evidence=[{"ok": True}],
            )
        ]


class FakeFailingPlugin(BasePlugin):
    def __init__(self):
        self.call_count = 0

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="fake_failing",
            description="Always raises",
            supported_entity_types=[TargetType.DOMAIN],
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        self.call_count += 1
        raise RuntimeError("boom")


class FakeSlowPlugin(BasePlugin):
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="fake_slow",
            description="Sleeps forever-ish",
            supported_entity_types=[TargetType.DOMAIN],
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        await asyncio.sleep(10)
        return []


@pytest.fixture
def pm():
    manager = PluginManager()
    # Reset singleton state for isolation
    manager._plugins.clear()
    manager._plugin_statuses.clear()
    manager._plugin_errors.clear()
    manager._result_cache.clear()
    manager._execution_stats.clear()
    manager._execution_timeout = 120.0
    return manager


@pytest.mark.asyncio
async def test_success_is_cached(pm):
    plugin = FakeSuccessPlugin()
    pm._plugins["fake_success"] = plugin
    pm._plugin_statuses["fake_success"] = "enabled"

    first = await pm.execute_plugin("fake_success", "example.com", TargetType.DOMAIN)
    second = await pm.execute_plugin("fake_success", "example.com", TargetType.DOMAIN)

    assert len(first) == 1
    assert len(second) == 1
    assert plugin.call_count == 1  # second call served from cache

    stats = pm.get_plugin_stats("fake_success")
    assert stats["runs"] == 1
    assert stats["failures"] == 0
    assert stats["last_error"] is None
    assert stats["last_duration_ms"] >= 0


@pytest.mark.asyncio
async def test_failure_raises_and_is_not_cached(pm):
    plugin = FakeFailingPlugin()
    pm._plugins["fake_failing"] = plugin
    pm._plugin_statuses["fake_failing"] = "enabled"

    with pytest.raises(PluginExecutionError) as exc_info:
        await pm.execute_plugin("fake_failing", "example.com", TargetType.DOMAIN)
    assert "boom" in str(exc_info.value)

    # Failures must NOT be cached - a retry should hit the plugin again
    with pytest.raises(PluginExecutionError):
        await pm.execute_plugin("fake_failing", "example.com", TargetType.DOMAIN)
    assert plugin.call_count == 2

    stats = pm.get_plugin_stats("fake_failing")
    assert stats["runs"] == 2
    assert stats["failures"] == 2
    assert "boom" in stats["last_error"]


@pytest.mark.asyncio
async def test_timeout_raises_plugin_execution_error(pm):
    pm._plugins["fake_slow"] = FakeSlowPlugin()
    pm._plugin_statuses["fake_slow"] = "enabled"
    pm._execution_timeout = 0.1

    with pytest.raises(PluginExecutionError) as exc_info:
        await pm.execute_plugin("fake_slow", "example.com", TargetType.DOMAIN)
    assert "timed out" in str(exc_info.value)

    stats = pm.get_plugin_stats("fake_slow")
    assert stats["failures"] == 1
    assert "timed out" in stats["last_error"]


@pytest.mark.asyncio
async def test_unknown_plugin_raises(pm):
    with pytest.raises(PluginExecutionError) as exc_info:
        await pm.execute_plugin("does_not_exist", "example.com", TargetType.DOMAIN)
    assert "not found" in str(exc_info.value)


@pytest.mark.asyncio
async def test_list_plugins_includes_stats(pm):
    pm._plugins["fake_success"] = FakeSuccessPlugin()
    pm._plugin_statuses["fake_success"] = "enabled"
    await pm.execute_plugin("fake_success", "example.com", TargetType.DOMAIN)

    listed = {p["name"]: p for p in pm.list_plugins()}
    assert "fake_success" in listed
    assert "stats" in listed["fake_success"]
    assert listed["fake_success"]["stats"]["runs"] == 1
