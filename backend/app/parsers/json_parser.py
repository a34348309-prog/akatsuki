import json
from typing import Any, Dict
from .base import BaseParser


class JSONParser(BaseParser):
    name = "json"
    version = "1.0.0"
    supported_format = "JSON"

    def can_parse(self, raw_log: str) -> float:
        log_str = raw_log.strip()
        if (log_str.startswith("{") and log_str.endswith("}")) or (log_str.startswith("[") and log_str.endswith("]")):
            try:
                json.loads(log_str)
                return 0.99
            except json.JSONDecodeError:
                return 0.1
        return 0.0

    def parse(self, raw_log: str) -> Dict[str, Any]:
        log_str = raw_log.strip()
        try:
            parsed = json.loads(log_str)
            if isinstance(parsed, dict):
                parsed["raw_event"] = raw_log
                if "vendor" not in parsed:
                    parsed["vendor"] = parsed.get("provider", parsed.get("source_vendor", "JSON Log"))
                return parsed
            elif isinstance(parsed, list) and len(parsed) > 0 and isinstance(parsed[0], dict):
                result = parsed[0]
                result["raw_event"] = raw_log
                return result
        except Exception:
            pass

        return {
            "raw_event": raw_log,
            "message": log_str,
            "source": "json",
            "vendor": "Generic JSON",
        }
