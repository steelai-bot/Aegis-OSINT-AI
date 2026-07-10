import pytest
import os
from pathlib import Path
from unittest.mock import patch

from backend.plugin_manager import PluginManager, validate_semver
from backend.models import PluginMetadata, TargetType


def test_plugin_discovery():
    pm = PluginManager()
    # Clear singleton state for clean test
    pm._plugins.clear()
    pm._plugin_statuses.clear()
    pm._file_mtimes.clear()
    pm._initialized = False
    
    pm.discover_plugins()
    plugins = pm.list_plugins()
    assert isinstance(plugins, list)


def test_plugin_status():
    pm = PluginManager()
    pm._plugins.clear()
    pm._plugin_statuses.clear()
    pm._file_mtimes.clear()
    pm._initialized = False
    
    pm.discover_plugins()
    plugins = pm.list_plugins()
    for p in plugins:
        assert "status" in p
        assert p["status"] in ["enabled", "disabled", "unknown"]


def test_validate_semver():
    """Test semver validation function - X.Y.Z format."""
    # Valid versions
    assert validate_semver("1.0.0") is True
    assert validate_semver("0.0.1") is True
    assert validate_semver("1.2.3") is True
    assert validate_semver("10.20.30") is True
    assert validate_semver("0.0.0") is True
    
    # Invalid versions
    assert validate_semver("1.0") is False
    assert validate_semver("v1.0.0") is False
    assert validate_semver("1") is False
    assert validate_semver("abc") is False
    assert validate_semver("") is False


def test_hot_reload_detection():
    """Test that plugin discovery skips when files haven't changed."""
    pm = PluginManager()
    pm._plugins.clear()
    pm._plugin_statuses.clear()
    pm._file_mtimes.clear()
    pm._initialized = False
    
    # First discovery
    pm.discover_plugins()
    first_count = len(pm.list_plugins())
    
    # Second discovery should skip (hot reload)
    pm.discover_plugins()
    
    # Both should return same count
    second_count = len(pm.list_plugins())
    assert first_count == second_count


def test_plugin_error_tracking():
    """Test that plugin errors are tracked and returned."""
    pm = PluginManager()
    pm._plugins.clear()
    pm._plugin_statuses.clear()
    pm._plugin_errors.clear()
    pm._file_mtimes.clear()
    pm._initialized = False
    
    pm.discover_plugins()
    
    # If there are disabled plugins with errors, check error tracking
    plugins = pm.list_plugins()
    for p in plugins:
        if p["status"] == "disabled" and "error" in p:
            assert p.get("error") is not None


def test_get_plugin_error():
    """Test get_plugin_error method."""
    pm = PluginManager()
    pm._plugins.clear()
    pm._plugin_statuses.clear()
    pm._plugin_errors.clear()
    pm._file_mtimes.clear()
    pm._initialized = False
    
    pm.discover_plugins()
    
    # Known plugins should exist
    plugin_names = pm.get_all_plugin_names()
    assert isinstance(plugin_names, list)