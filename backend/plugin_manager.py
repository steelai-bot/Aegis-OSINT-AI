import asyncio
import importlib
import inspect
import logging
import os
import pkgutil
import re
import time
from pathlib import Path
from typing import Any, Optional

from backend.models import PluginResponse, TargetType
from backend.plugins.base import BasePlugin, PluginExecutionError

logger = logging.getLogger(__name__)

# Semver regex pattern for version validation (simplified but robust)
SEMVER_PATTERN = re.compile(
    r'^([0-9]+)\.([0-9]+)\.([0-9]+)'
    r'(?:-([0-9A-Za-z-.]+))?'
    r'(?:\+([0-9A-Za-z-.]+))?$'
)


def validate_semver(version: str) -> bool:
    """Validate that a version string follows semantic versioning (X.Y.Z format)."""
    if not version:
        return False
    parts = version.split('.')
    if len(parts) < 3:
        return False
    try:
        major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
        return major >= 0 and minor >= 0 and patch >= 0
    except (ValueError, IndexError):
        return False


class PluginManager:
    """
    Singleton manager for discovering and executing OSINT plugins.
    Supports hot reload detection, version validation, dependency checking, and result caching.
    """
    _instance: Optional['PluginManager'] = None
    _initialized: bool

    def __new__(cls):

        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._plugins: dict[str, BasePlugin] = {}
        self._plugin_statuses: dict[str, str] = {}
        self._plugin_errors: dict[str, str] = {}
        self._file_mtimes: dict[str, float] = {}
        self._result_cache: dict[str, tuple[list[PluginResponse], float]] = {}
        self._cache_ttl: float = 3600.0
        # Per-plugin execution timeout (seconds) - prevents a hung plugin
        # from blocking the whole investigation.
        self._execution_timeout: float = 120.0
        # Runtime execution statistics keyed by plugin name.
        self._execution_stats: dict[str, dict[str, Any]] = {}
        self._initialized = True

        logger.info("PluginManager initialized.")

    def _validate_plugin_metadata(self, plugin_instance: BasePlugin, plugin_name: str) -> str | None:
        """Validate plugin metadata including version and dependencies. Returns error message or None."""
        metadata = plugin_instance.metadata

        # Validate semver format
        if not validate_semver(metadata.version):
            return f"Invalid semver version format: {metadata.version}"

        return None

    def _check_plugin_dependencies(self, plugin_name: str, dependencies: list[str]) -> str | None:
        """Check if required plugin dependencies exist. Returns error message or None."""
        missing_deps = []
        for dep in dependencies:
            if dep not in self._plugins:
                missing_deps.append(dep)

        if missing_deps:
            return f"Missing dependencies: {', '.join(missing_deps)}"
        return None

    def discover_plugins(self, package_path: str = "backend.plugins", watch_for_changes: bool = True):
        """
        Dynamically discovers and instantiates plugins from the specified package.

        Args:
            package_path: Path to the plugins package
            watch_for_changes: If True, only rediscover if file modification times have changed
        """
        # Hot reload detection - skip if no changes and watch is enabled
        if watch_for_changes:
            try:
                package = importlib.import_module(package_path)
                plugins_dir = Path(package.__path__[0])
                current_mtimes: dict[str, float] = {}

                for py_file in plugins_dir.glob("*.py"):
                    current_mtimes[str(py_file)] = py_file.stat().st_mtime

                # If mtimes haven't changed and we have plugins, skip discovery
                if self._plugins and current_mtimes == self._file_mtimes:
                    logger.debug("Plugin hot reload: No file changes detected, skipping rediscovery")
                    return

                self._file_mtimes = current_mtimes
            except Exception as e:
                logger.warning(f"Hot reload detection failed, proceeding with full discovery: {e}")

        # Clear and rebuild plugin registry
        self._plugins.clear()
        self._plugin_statuses.clear()
        self._plugin_errors.clear()

        try:
            package = importlib.import_module(package_path)
            for _loader, module_name, _is_pkg in pkgutil.iter_modules(package.__path__):
                if module_name == "base":
                    continue

                full_module_name = f"{package_path}.{module_name}"
                try:
                    module = importlib.import_module(full_module_name)

                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if issubclass(obj, BasePlugin) and obj is not BasePlugin:
                            plugin_instance = obj()

                            # Validate Metadata exists
                            if not hasattr(plugin_instance, 'metadata') or plugin_instance.metadata is None:
                                logger.error(f"Plugin {name} missing metadata. Skipping.")
                                continue

                            plugin_name = plugin_instance.metadata.name

                            # Duplicate check
                            if plugin_name in self._plugins:
                                logger.error(f"Duplicate plugin name detected: {plugin_name}. Skipping {name}.")
                                continue

                            # Validate version format
                            version_error = self._validate_plugin_metadata(plugin_instance, plugin_name)
                            if version_error:
                                logger.error(f"Plugin {plugin_name} validation failed: {version_error}. Skipping.")
                                self._plugin_errors[plugin_name] = version_error
                                continue

                            # Check credentials and dependencies
                            status = "enabled"
                            error_msg = None

                            # Check required API keys
                            for key in plugin_instance.metadata.required_api_keys:
                                if not os.getenv(key):
                                    error_msg = f"Missing required credential: {key}"
                                    status = "disabled"
                                    break

                            # Check plugin dependencies (only if enabled)
                            if status == "enabled" and plugin_instance.metadata.dependencies:
                                dep_error = self._check_plugin_dependencies(
                                    plugin_name,
                                    plugin_instance.metadata.dependencies
                                )
                                if dep_error:
                                    error_msg = dep_error
                                    status = "disabled"

                            self._plugins[plugin_name] = plugin_instance
                            self._plugin_statuses[plugin_name] = status
                            if error_msg:
                                self._plugin_errors[plugin_name] = error_msg
                            logger.info(f"Discovered plugin: {plugin_name} (Status: {status})")

                except Exception as e:
                    logger.error(f"Failed to load module {full_module_name}: {e}", exc_info=True)

            logger.info(f"Discovery complete. Found {len(self._plugins)} plugins.")
        except Exception as e:
            logger.error(f"Error during plugin discovery: {e}", exc_info=True)

    def get_plugin(self, plugin_name: str) -> BasePlugin | None:
        """Retrieve a plugin by its name."""
        return self._plugins.get(plugin_name)

    def _record_execution(
        self,
        plugin_name: str,
        duration_ms: float,
        success: bool,
        error: str | None = None,
    ) -> None:
        """Record runtime statistics for a plugin execution."""
        stats = self._execution_stats.setdefault(
            plugin_name,
            {"runs": 0, "failures": 0, "last_error": None, "last_duration_ms": 0.0, "last_run_at": None},
        )
        stats["runs"] += 1
        if not success:
            stats["failures"] += 1
            stats["last_error"] = error
        else:
            stats["last_error"] = None
        stats["last_duration_ms"] = round(duration_ms, 2)
        stats["last_run_at"] = time.time()

    def get_plugin_stats(self, plugin_name: str | None = None) -> dict[str, Any]:
        """Return runtime execution stats for one plugin or all plugins."""
        if plugin_name is not None:
            return self._execution_stats.get(plugin_name, {})
        return dict(self._execution_stats)

    async def execute_plugin(self, plugin_name: str, query: str, target_type: TargetType) -> list[PluginResponse]:
        """
        Execute a specific plugin with TTL-based result caching, a per-plugin
        execution timeout, and runtime statistics tracking.

        Only successful executions are cached - failures raise PluginExecutionError
        so callers (e.g. the engine) can log proper ERROR timeline events instead
        of silently treating a crash as "no results".
        """
        cache_key = f"{plugin_name}:{query}:{target_type.value}"
        now = time.time()

        if cache_key in self._result_cache:
            results, cached_at = self._result_cache[cache_key]
            if now - cached_at < self._cache_ttl:
                logger.debug(f"Cache hit for {cache_key}")
                return results
            else:
                del self._result_cache[cache_key]

        plugin = self.get_plugin(plugin_name)
        if not plugin:
            raise PluginExecutionError(plugin_name, "Plugin not found in registry")

        if target_type not in plugin.metadata.supported_entity_types:
            logger.warning(
                f"Plugin '{plugin_name}' does not officially support target type "
                f"'{target_type.value}', executing anyway"
            )

        started = time.perf_counter()
        try:
            logger.info(f"Executing plugin: {plugin_name} for query: {query}")
            results = await asyncio.wait_for(
                plugin.execute(query, target_type),
                timeout=self._execution_timeout,
            )
            duration_ms = (time.perf_counter() - started) * 1000
            self._record_execution(plugin_name, duration_ms, success=True)
            self._result_cache[cache_key] = (results, now)
            return results
        except TimeoutError as e:
            duration_ms = (time.perf_counter() - started) * 1000
            msg = f"Execution timed out after {self._execution_timeout}s"
            self._record_execution(plugin_name, duration_ms, success=False, error=msg)
            logger.error(f"Plugin '{plugin_name}' {msg}")
            raise PluginExecutionError(plugin_name, msg, cause=e) from e
        except PluginExecutionError:
            duration_ms = (time.perf_counter() - started) * 1000
            self._record_execution(plugin_name, duration_ms, success=False, error="Plugin raised PluginExecutionError")
            raise
        except Exception as e:
            duration_ms = (time.perf_counter() - started) * 1000
            self._record_execution(plugin_name, duration_ms, success=False, error=str(e))
            logger.error(f"Error executing plugin '{plugin_name}': {e}", exc_info=True)
            raise PluginExecutionError(plugin_name, str(e), cause=e) from e


    def list_plugins(self) -> list[dict[str, Any]]:
        """Return metadata, status, and runtime stats for all discovered plugins."""
        result = []
        for name, plugin in self._plugins.items():
            data = plugin.metadata.model_dump()
            data["status"] = self._plugin_statuses.get(name, "unknown")
            if name in self._plugin_errors:
                data["error"] = self._plugin_errors[name]
            if name in self._execution_stats:
                data["stats"] = self._execution_stats[name]
            result.append(data)
        return result


    def get_all_plugin_names(self) -> list[str]:
        """Return names of all discovered plugins."""
        return list(self._plugins.keys())

    def get_plugin_error(self, plugin_name: str) -> str | None:
        """Return the error message for a plugin, if any."""
        return self._plugin_errors.get(plugin_name)
