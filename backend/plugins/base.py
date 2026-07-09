from abc import ABC, abstractmethod
from typing import Any, Dict, List
from backend.models import PluginMetadata, PluginResponse, TargetType

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
    async def execute(self, query: str, target_type: TargetType) -> List[PluginResponse]:
        """
        Execute the plugin's search logic.
        
        Args:
            query: The target string (domain, IP, email, etc.)
            target_type: The type of the target.
            
        Returns:
            A list of PluginResponse objects containing the findings.
        """
        pass