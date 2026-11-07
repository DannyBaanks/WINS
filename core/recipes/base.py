"""
WINS Core - Base Recipe Interface
All transmutation recipes (Electron, PyInstaller, .NET, etc.) inherit from this base.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseRecipe(ABC):
    name: str = "base"
    description: str = "Base Transmutation Recipe"

    @abstractmethod
    def can_handle(self, triage: Dict[str, Any]) -> bool:
        """Determines if this recipe can process the binary taxonomy."""
        pass

    @abstractmethod
    def transmute(self, triage: Dict[str, Any], dest_dir: str, options: Dict[str, Any]) -> bool:
        """Executes the de-layering and native re-hosting pipeline."""
        pass
