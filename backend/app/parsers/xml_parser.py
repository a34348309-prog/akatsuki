import xml.etree.ElementTree as ET
from typing import Any, Dict
from .base import BaseParser


class XMLParser(BaseParser):
    name = "xml"
    version = "1.0.0"
    supported_format = "XML"

    def can_parse(self, raw_log: str) -> float:
        log_str = raw_log.strip()
        if log_str.startswith("<") and log_str.endswith(">") and not log_str.startswith("<PRI>"):
            try:
                ET.fromstring(log_str)
                return 0.95
            except ET.ParseError:
                return 0.1
        return 0.0

    def parse(self, raw_log: str) -> Dict[str, Any]:
        log_str = raw_log.strip()
        try:
            root = ET.fromstring(log_str)
            parsed: Dict[str, Any] = {
                "raw_event": raw_log,
                "vendor": "XML Event Log",
                "source": root.tag,
                "message": f"XML Event element: {root.tag}",
            }
            
            for child in root:
                tag = child.tag.split("}")[-1]  # Strip namespace
                parsed[tag] = child.text or ""

            return parsed
        except Exception:
            return {
                "raw_event": raw_log,
                "message": log_str,
                "source": "xml",
                "vendor": "Generic XML",
            }
