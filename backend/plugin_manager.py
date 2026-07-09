import importlib
import inspect
import pkgutil
import logging
from typing import Dict, List, Optional, Type
from backend.plugins.base import BasePlugin
from backend.models import PluginMetadata, PluginResponse, TargetType

logger = logging.getLogger(__name__)

class PluginManager:
    """
    Singleton manager for discovering and executing OSINT plugins.
    """
    _instance: Optional['PluginManager'] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(PluginManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._plugins: Dict[str, BasePlugin] = {}
        self._initialized = True
        logger.info("PluginManager initialized.")

    def discover_plugins(self, package_path: str = "backend.plugins"):
        """
        Dynamically discovers and instantiates plugins from the specified package.
        """
        self._plugins.clear()
        try:
            package = importlib.import_module(package_path)
            for loader, module_name, is_pkg in pkgutil.iter_modules(package.__path__):
                # Skip the base plugin module
                if module_name == "base":
                    continue
                
                full_module_name = f"{package_path}.{module_name}"
                module = importlib.import_module(full_module_name)
                
                # Find all classes in the module that inherit from BasePlugin
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, BasePlugin) and obj is not BasePlugin:
                        try:
                            plugin_instance = obj()
                            plugin_name = plugin_instance.metadata.name
                            self._plugins[plugin_name] = plugin_instance
                            logger.info(f"Discovered plugin: {plugin_name} from {full_module_name}")
                        except Exception as e:
                            logger.error(f"Failed to instantiate plugin {name} from {full_module_name}: {e}")
            
            logger.info(f"Discovery complete. Found {len(self._plugins)} plugins.")
        except Exception as e:
            logger.error(f"Error during plugin discovery: {e}")

    def get_plugin(self, plugin_name: str) -> Optional[BasePlugin]:
        """Retrieve a plugin by its name."""
        return self._plugins.get(plugin_name)

    async def execute_plugin(self, plugin_name: str, query: str, target_type: TargetType) -> List[PluginResponse]:
        """
        Execute a specific plugin.
        """
        plugin = self.get_plugin(plugin_name)
        if not plugin:
            logger.error(f"Plugin '{plugin_name}' not found.")
            return []

        try:
            logger.info(f"Executing plugin: {plugin_name} for query: {query}")
            return await plugin.execute(query, target_type)
        except Exception as e:
            logger.error(f"Error executing plugin '{plugin_name}': {e}")
            return []

    def list_plugins(self) -> List[PluginMetadata]:
        """Return metadata for all discovered plugins."""
        return [p.metadata for p in self._plugins.values()]

    def get_all_plugin_names(self) -> List[str]:
        """Return names of all discovered plugins."""
        return list(self._plugins.keys())