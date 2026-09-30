from typing import Dict, List, Optional, Tuple
from .base import BaseParser
from .syslog_parser import SyslogParser
from .json_parser import JSONParser
from .cef_parser import CEFParser
from .leef_parser import LEEFParser
from .csv_parser import CSVParser
from .xml_parser import XMLParser


class ParserRegistry:
    """
    Plugin-capable Parser Registry for ULPF.
    Enables plug-and-play onboarding of new parsers without modifying core pipeline code.
    """
    def __init__(self):
        self._parsers: Dict[str, BaseParser] = {}
        # Register default standard parsers
        self.register_parser(SyslogParser())
        self.register_parser(JSONParser())
        self.register_parser(CEFParser())
        self.register_parser(LEEFParser())
        self.register_parser(CSVParser())
        self.register_parser(XMLParser())

    def register_parser(self, parser: BaseParser) -> None:
        """Register a new parser plugin into the registry."""
        self._parsers[parser.name] = parser

    def get_parser(self, name: str) -> Optional[BaseParser]:
        """Retrieve parser by name."""
        return self._parsers.get(name)

    def list_parsers(self) -> List[Dict[str, str]]:
        """Return list of all registered parsers and versions."""
        return [
            {
                "name": p.name,
                "version": p.version,
                "supported_format": p.supported_format,
            }
            for p in self._parsers.values()
        ]

    def detect_format(self, raw_log: str) -> Tuple[BaseParser, float, str]:
        """
        Evaluate raw log against all registered parsers and return best matching parser.
        Returns: (best_parser, confidence_score, format_name)
        """
        best_parser: BaseParser = self._parsers["syslog"]  # Default fallback
        max_confidence = 0.0

        for parser in self._parsers.values():
            confidence = parser.can_parse(raw_log)
            if confidence > max_confidence:
                max_confidence = confidence
                best_parser = parser

        # Fallback if no parser matches with confidence > 0.3
        if max_confidence < 0.3:
            return self._parsers["syslog"], max_confidence, "Syslog (Fallback)"

        return best_parser, max_confidence, best_parser.supported_format


# Singleton instance
default_registry = ParserRegistry()
