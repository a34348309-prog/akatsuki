import re
from typing import Any, Dict
from .base import BaseParser


class LEEFParser(BaseParser):
    name = "leef"
    version = "1.0.0"
    supported_format = "LEEF"

    # LEEF:Version|Vendor|Product|Version|EventID|Extension
    LEEF_HEADER_PATTERN = re.compile(
        r"^LEEF:(?P<version>[0-9\.]+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<device_version>[^|]*)\|(?P<event_id>[^|]*)\|(?:(?P<extension>.*))?$",
        re.DOTALL
    )

    def can_parse(self, raw_log: str) -> float:
        log_str = raw_log.strip()
        if log_str.startswith("LEEF:") or " LEEF:1.0|" in log_str or " LEEF:2.0|" in log_str:
            return 0.98
        if log_str.count("|") >= 4 and "LEEF" in log_str[:15]:
            return 0.85
        return 0.0

    def parse(self, raw_log: str) -> Dict[str, Any]:
        log_str = raw_log.strip()
        if "LEEF:" in log_str and not log_str.startswith("LEEF:"):
            log_str = log_str[log_str.find("LEEF:"):]

        match = self.LEEF_HEADER_PATTERN.match(log_str)
        if not match:
            return {
                "raw_event": raw_log,
                "message": log_str,
                "source": "LEEF",
                "vendor": "Generic LEEF",
            }

        data = match.groupdict()
        extensions = self._parse_extensions(data.get("extension") or "")

        result = {
            "raw_event": raw_log,
            "leef_version": data.get("version"),
            "vendor": data.get("vendor") or "Generic LEEF",
            "product": data.get("product"),
            "device_version": data.get("device_version"),
            "event_id": data.get("event_id"),
            "source": data.get("product") or "LEEF Device",
            "message": extensions.get("msg") or extensions.get("message") or f"LEEF Event {data.get('event_id')}",
        }

        key_mapping = {
            "src": "src_ip",
            "srcPort": "src_port",
            "dst": "dst_ip",
            "dstPort": "dst_port",
            "usrName": "username",
            "user": "username",
            "proto": "protocol",
            "action": "action",
            "sev": "severity",
            "devTime": "timestamp",
            "cat": "category",
        }

        for ext_key, ext_val in extensions.items():
            mapped_key = key_mapping.get(ext_key)
            if mapped_key:
                result[mapped_key] = ext_val
            else:
                result[ext_key] = ext_val

        return result

    def _parse_extensions(self, ext_str: str) -> Dict[str, str]:
        extensions = {}
        if not ext_str:
            return extensions

        # LEEF 2.0 allows custom delimiter specified in header or defaults to TAB/x09
        delimiter = "\t" if "\t" in ext_str else " "
        tokens = ext_str.split(delimiter)
        for token in tokens:
            if "=" in token:
                k, v = token.split("=", 1)
                extensions[k.strip()] = v.strip().strip('"\'')
        return extensions
