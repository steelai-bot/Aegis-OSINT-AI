import importlib
import inspect
import pkgutil
import logging
from typing import Dict, List, Optional, Type, Any
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
        self._plugin_statuses: Dict[str, str] = {}
        self._initialized = True
        logger.info("PluginManager initialized.")

    def discover_plugins(self, package_path: str = "backend.plugins"):
        """
        Dynamically discovers and instantiates plugins from the specified package.
        """
        self._plugins.clear()
        self._plugin_statuses.clear()
        
        from backend.provider_manager import ProviderManager
        import os
        provider_mgr = ProviderManager()
        
        try:
            package = importlib.import_module(package_path)
            for loader, module_name, is_pkg in pkgutil.iter_modules(package.__path__):
                if module_name == "base":
                    continue
                
                full_module_name = f"{package_path}.{module_name}"
                try:
                    module = importlib.import_module(full_module_name)
                    
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if issubclass(obj, BasePlugin) and obj is not BasePlugin:
                            plugin_instance = obj()
                            
                            # Validate Metadata
                            if not hasattr(plugin_instance, 'metadata') or plugin_instance.metadata is None:
                                logger.error(f"Plugin {name} missing metadata. Skipping.")
                                continue
                            
                            plugin_name = plugin_instance.metadata.name
                            
                            # Duplicate check
                            if plugin_name in self._plugins:
                                logger.error(f"Duplicate plugin name detected: {plugin_name}. Skipping {name}.")
                                continue
                                
                            # Check credentials
                            status = "enabled"
                            for key in plugin_instance.metadata.required_api_keys:
                                if not os.getenv(key):
                                    logger.warning(f"Plugin {plugin_name} missing required credential: {key}. Disabling.")
                                    status = "disabled"
                                    break
                            
                            self._plugins[plugin_name] = plugin_instance
                            self._plugin_statuses[plugin_name] = status
                            logger.info(f"Discovered plugin: {plugin_name} (Status: {status})")
                            
                except Exception as e:
                    logger.error(f"Failed to load module {full_module_name}: {e}")
            
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
            raise

    def list_plugins(self) -> List[Dict[str, Any]]:
        """Return metadata for all discovered plugins."""
        result = []
        for name, plugin in self._plugins.items():
            data = plugin.metadata.dict()
            data["status"] = self._plugin_statuses.get(name, "unknown")
            result.append(data)
        return result

    def get_all_plugin_names(self) -> List[str]:
        """Return names of all discovered plugins."""
        return list(self._plugins.keys())