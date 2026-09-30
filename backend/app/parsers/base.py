from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseParser(ABC):
    """
    Abstract Base Class for ULPF Log Parsers.
    Custom parsers (XML, Cisco, Snort, Palo Alto) inherit from this base class
    and register with ParserRegistry to achieve plug-and-play expansion without modifying core logic.
    """
    name: str = "base"
    version: str = "1.0.0"
    supported_format: str = "Unknown"

    @abstractmethod
    def can_parse(self, raw_log: str) -> float:
        """
        Evaluate confidence score (0.0 to 1.0) that raw_log matches this parser's format.
        """
        pass

    @abstractmethod
    def parse(self, raw_log: str) -> Dict[str, Any]:
        """
        Parse raw log text into an intermediate raw parsed attribute dictionary.
        All unmapped/vendor-specific fields must be returned intact.
        """
        pass
