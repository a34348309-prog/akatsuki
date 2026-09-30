import re
from typing import Any, Dict
from .base import BaseParser


class CEFParser(BaseParser):
    name = "cef"
    version = "1.0.0"
    supported_format = "CEF"

    # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    CEF_HEADER_PATTERN = re.compile(
        r"^CEF:(?P<version>\d+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<device_version>[^|]*)\|(?P<signature_id>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|(?:(?P<extension>.*))?$",
        re.DOTALL
    )

    def can_parse(self, raw_log: str) -> float:
        log_str = raw_log.strip()
        if log_str.startswith("CEF:") or " CEF:0|" in log_str or " CEF:1|" in log_str:
            return 0.98
        if log_str.count("|") >= 6 and "CEF" in log_str[:15]:
            return 0.85
        return 0.0

    def parse(self, raw_log: str) -> Dict[str, Any]:
        log_str = raw_log.strip()
        # Handle prefix if syslog wrapper is present
        if "CEF:" in log_str and not log_str.startswith("CEF:"):
            log_str = log_str[log_str.find("CEF:"):]

        match = self.CEF_HEADER_PATTERN.match(log_str)
        if not match:
            return {
                "raw_event": raw_log,
                "message": log_str,
                "source": "CEF",
                "vendor": "Generic CEF",
            }

        data = match.groupdict()
        extensions = self._parse_extensions(data.get("extension") or "")

        result = {
            "raw_event": raw_log,
            "cef_version": data.get("version"),
            "vendor": data.get("vendor") or "Generic CEF",
            "product": data.get("product"),
            "device_version": data.get("device_version"),
            "signature_id": data.get("signature_id"),
            "event_name": data.get("name"),
            "severity": data.get("severity"),
            "source": data.get("product") or "CEF Firewall",
            "message": data.get("name") or extensions.get("msg", ""),
        }

        # Map standard CEF extension keys
        key_mapping = {
            "src": "src_ip",
            "sourceAddress": "src_ip",
            "spt": "src_port",
            "sourcePort": "src_port",
            "dst": "dst_ip",
            "destinationAddress": "dst_ip",
            "dpt": "dst_port",
            "destinationPort": "dst_port",
            "suser": "username",
            "sourceUserId": "username",
            "duser": "destination_username",
            "shost": "hostname",
            "dhost": "destination_hostname",
            "proto": "protocol",
            "act": "action",
            "outcome": "status",
            "msg": "message",
            "rt": "timestamp",
            "end": "timestamp",
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
        """Parse CEF extension key=value pairs handling escaped equal signs and spaces."""
        extensions = {}
        if not ext_str:
            return extensions

        # Tokenize key=value pairs
        tokens = re.split(r'\s+(?=[a-zA-Z0-9_\.]+=)', ext_str.strip())
        for token in tokens:
            if "=" in token:
                k, v = token.split("=", 1)
                extensions[k.strip()] = v.strip().strip('"\'')
        return extensions
