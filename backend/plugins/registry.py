"""Plugin discovery and registry utilities."""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Iterable

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
    def __init__(self, plugin_classes: Iterable[type[BasePlugin]] | None = None) -> None:
        self.plugin_classes = list(plugin_classes or discover_plugins())

    def enabled_plugins(self) -> list[BasePlugin]:
        return [plugin_class() for plugin_class in self.plugin_classes if plugin_class.enabled]
