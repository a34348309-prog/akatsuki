import re
from typing import Any, Dict
from .base import BaseParser


class SyslogParser(BaseParser):
    name = "syslog"
    version = "1.0.0"
    supported_format = "Syslog"

    # RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
    RFC5424_PATTERN = re.compile(
        r"^<(?P<pri>\d{1,3})>(?P<version>\d+)\s+"
        r"(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+"
        r"(?P<appname>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s*"
        r"(?P<sd>\[.*?\]|-)?\s*(?P<msg>.*)$"
    )

    # RFC 3164: <PRI>TIMESTAMP HOSTNAME APP[PID]: MSG
    RFC3164_PATTERN = re.compile(
        r"^<(?P<pri>\d{1,3})>?"
        r"(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S*)\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<appname>[a-zA-Z0-9_\-\.]+)(?:\[(?P<procid>\d+)\])?:\s*"
        r"(?P<msg>.*)$"
    )

    def can_parse(self, raw_log: str) -> float:
        log_str = raw_log.strip()
        if self.RFC5424_PATTERN.match(log_str):
            return 0.95
        if self.RFC3164_PATTERN.match(log_str):
            return 0.90
        if log_str.startswith("<") and ">" in log_str[:5]:
            return 0.70
        if any(month in log_str for month in ["Jan ", "Feb ", "Mar ", "Apr ", "May ", "Jun ", "Jul ", "Aug ", "Sep ", "Oct ", "Nov ", "Dec "]):
            return 0.50
        return 0.0

    def parse(self, raw_log: str) -> Dict[str, Any]:
        log_str = raw_log.strip()
        match5424 = self.RFC5424_PATTERN.match(log_str)
        if match5424:
            data = match5424.groupdict()
            pri = int(data.get("pri", 13))
            facility = pri // 8
            severity = pri % 8
            return {
                "raw_event": raw_log,
                "syslog_pri": pri,
                "syslog_facility": facility,
                "syslog_severity": severity,
                "syslog_version": data.get("version"),
                "timestamp": data.get("timestamp"),
                "hostname": data.get("hostname"),
                "app_name": data.get("appname"),
                "proc_id": data.get("procid"),
                "msg_id": data.get("msgid"),
                "structured_data": data.get("sd"),
                "message": data.get("msg"),
                "source": data.get("appname") or "syslog",
                "vendor": "Generic Syslog",
            }

        match3164 = self.RFC3164_PATTERN.match(log_str)
        if match3164:
            data = match3164.groupdict()
            pri = int(data.get("pri", 13)) if data.get("pri") else 13
            facility = pri // 8
            severity = pri % 8
            return {
                "raw_event": raw_log,
                "syslog_pri": pri,
                "syslog_facility": facility,
                "syslog_severity": severity,
                "timestamp": data.get("timestamp"),
                "hostname": data.get("hostname"),
                "app_name": data.get("appname"),
                "proc_id": data.get("procid"),
                "message": data.get("msg"),
                "source": data.get("appname") or "syslog",
                "vendor": "Generic Syslog",
            }

        # Fallback parsing for loose syslog
        return {
            "raw_event": raw_log,
            "message": log_str,
            "source": "syslog",
            "vendor": "Generic Syslog",
        }
