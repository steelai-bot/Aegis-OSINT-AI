from abc import ABC, abstractmethod

from backend.models import PluginMetadata, PluginResponse, TargetType


class PluginExecutionError(Exception):
    """Raised when a plugin fails during execution.

    Carries the plugin name and the original cause so the engine/manager
    can log structured timeline events without swallowing failures.
    """

    def __init__(self, plugin_name: str, message: str, cause: BaseException | None = None):
        self.plugin_name = plugin_name
        self.cause = cause
        super().__init__(f"[{plugin_name}] {message}")


class BasePlugin(ABC):
    """
    Abstract Base Class for all OSINT plugins.
    Each plugin must implement the metadata property and the execute method.
    """

    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Return the plugin's metadata."""
        pass

    @abstractmethod
    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        """
        Execute the plugin's search logic.

        Args:
            query: The target string (domain, IP, email, etc.)
            target_type: The type of the target.

        Returns:
            A list of PluginResponse objects containing the findings.
        """
        pass
