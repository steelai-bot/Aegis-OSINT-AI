"""Plugin discovery and registry utilities."""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Iterable
from typing import Any

from backend.plugins.base import BasePlugin


def discover_plugins(package_name: str = "backend.plugins") -> list[type[BasePlugin]]:
    """Discover concrete plugin classes in the plugins package."""

    package = importlib.import_module(package_name)
    discovered: list[type[BasePlugin]] = []
    for module_info in pkgutil.iter_modules(package.__path__, package.__name__ + "."):
        if module_info.name.endswith((".base", ".registry")):
            continue
        module = importlib.import_module(module_info.name)
        for value in vars(module).values():
            if isinstance(value, type) and issubclass(value, BasePlugin) and value is not BasePlugin:
                discovered.append(value)
    return discovered


class PluginRegistry:
    def __init__(
        self,
        plugin_classes: Iterable[type[BasePlugin]] | None = None,
        *,
        enabled_plugin_names: Iterable[str] | None = None,
        disabled_plugin_names: Iterable[str] | None = None,
        plugin_configs: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self.plugin_classes = list(plugin_classes or discover_plugins())
        self.enabled_plugin_names = set(enabled_plugin_names) if enabled_plugin_names is not None else None
        self.disabled_plugin_names = set(disabled_plugin_names or [])
        self.plugin_configs = plugin_configs or {}

    def is_enabled(self, plugin_class: type[BasePlugin]) -> bool:
        if not plugin_class.enabled:
            return False
        if plugin_class.name in self.disabled_plugin_names:
            return False
        if self.enabled_plugin_names is not None and plugin_class.name not in self.enabled_plugin_names:
            return False
        return True

    def enabled_plugins(self) -> list[BasePlugin]:
        return [
            plugin_class(config=self.plugin_configs.get(plugin_class.name, {}))
            for plugin_class in self.plugin_classes
            if self.is_enabled(plugin_class)
        ]
