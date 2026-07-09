import pytest
from backend.plugin_manager import PluginManager
from backend.models import PluginMetadata, TargetType

def test_plugin_discovery():
    pm = PluginManager()
    pm.discover_plugins()
    # It should discover at least some plugins if they exist
    plugins = pm.list_plugins()
    assert isinstance(plugins, list)
    
def test_plugin_status():
    pm = PluginManager()
    pm.discover_plugins()
    plugins = pm.list_plugins()
    for p in plugins:
        assert "status" in p
        assert p["status"] in ["enabled", "disabled", "unknown"]
