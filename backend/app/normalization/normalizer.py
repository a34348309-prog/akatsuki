import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Dict
from app.models.event import UniversalEvent


class EventNormalizer:
    """
    Normalizes raw parsed dictionary into the ULPF Universal Event Schema.
    Preserves all unmapped source fields losslessly in source_fields.
    """
    NORMALIZATION_VERSION = "1.0.0"

    # Known standard fields defined in Universal Event Schema
    UNIVERSAL_FIELDS = {
        "event_id", "timestamp", "source", "source_type", "vendor", "event_type",
        "category", "severity", "src_ip", "src_port", "dst_ip", "dst_port",
        "protocol", "username", "hostname", "action", "status", "message",
        "raw_event", "parser", "parser_version", "normalization_version",
        "event_hash", "provenance_id", "source_fields", "cleaning_notes", "validation_status"
    }

    def normalize(
        self,
        parsed_data: Dict[str, Any],
        parser_name: str,
        parser_version: str,
        raw_log: str,
        provenance_id: str
    ) -> UniversalEvent:
        raw_event_str = raw_log if raw_log else parsed_data.get("raw_event", "")
        event_hash = f"sha256:{hashlib.sha256(raw_event_str.encode('utf-8')).hexdigest()}"
        
        # Generate event_id if not present
        event_id = parsed_data.get("event_id") or parsed_data.get("id") or f"evt-{uuid.uuid4().hex[:8]}"

        # Standardize severity
        raw_sev = parsed_data.get("severity") or parsed_data.get("syslog_severity") or parsed_data.get("sev")
        severity = self._normalize_severity(raw_sev)

        # Standardize status
        raw_status = parsed_data.get("status") or parsed_data.get("outcome") or parsed_data.get("act")
        status = self._normalize_status(raw_status, parsed_data.get("message", ""))

        # Extract timestamps
        timestamp = self._normalize_timestamp(parsed_data.get("timestamp") or parsed_data.get("rt") or parsed_data.get("devTime"))

        # Extract IP addresses & Ports
        src_ip = parsed_data.get("src_ip") or parsed_data.get("ip") or parsed_data.get("sourceAddress") or parsed_data.get("src")
        dst_ip = parsed_data.get("dst_ip") or parsed_data.get("destination") or parsed_data.get("destinationAddress") or parsed_data.get("dst")
        
        src_port = self._safe_int(parsed_data.get("src_port") or parsed_data.get("spt"))
        dst_port = self._safe_int(parsed_data.get("dst_port") or parsed_data.get("dpt"))

        # User and Host
        username = parsed_data.get("username") or parsed_data.get("user") or parsed_data.get("suser")
        hostname = parsed_data.get("hostname") or parsed_data.get("shost") or parsed_data.get("host")
        
        # Event type & Category
        event_type = parsed_data.get("event_type") or parsed_data.get("event") or parsed_data.get("event_name") or "Security Event"
        category = parsed_data.get("category") or parsed_data.get("cat") or "Audit"
        source = parsed_data.get("source") or parsed_data.get("app_name") or parser_name
        source_type = parsed_data.get("source_type") or self._infer_source_type(source, event_type)
        vendor = parsed_data.get("vendor") or "Generic"
        action = parsed_data.get("action") or parsed_data.get("act")
        protocol = parsed_data.get("protocol") or parsed_data.get("proto")
        message = parsed_data.get("message") or parsed_data.get("msg") or raw_event_str

        # Lossless source_fields preservation: collect all keys not in universal schema
        source_fields: Dict[str, Any] = {}
        for key, val in parsed_data.items():
            if key not in self.UNIVERSAL_FIELDS and val is not None:
                source_fields[key] = val

        return UniversalEvent(
            event_id=event_id,
            timestamp=timestamp,
            source=str(source),
            source_type=str(source_type),
            vendor=str(vendor),
            event_type=str(event_type),
            category=str(category),
            severity=severity,
            src_ip=str(src_ip) if src_ip else None,
            src_port=src_port,
            dst_ip=str(dst_ip) if dst_ip else None,
            dst_port=dst_port,
            protocol=str(protocol) if protocol else None,
            username=str(username) if username else None,
            hostname=str(hostname) if hostname else None,
            action=str(action) if action else None,
            status=status,
            message=str(message),
            raw_event=raw_event_str,
            parser=parser_name,
            parser_version=parser_version,
            normalization_version=self.NORMALIZATION_VERSION,
            event_hash=event_hash,
            provenance_id=provenance_id,
            source_fields=source_fields,
            cleaning_notes=[],
            validation_status="VALID",
        )

    def _normalize_severity(self, raw_sev: Any) -> str:
        if raw_sev is None:
            return "Informational"
        s = str(raw_sev).strip().lower()
        if s in ["0", "1", "emerg", "emergency", "alert", "crit", "critical"]:
            return "Critical"
        if s in ["2", "3", "err", "error", "high", "h"]:
            return "High"
        if s in ["4", "warn", "warning", "medium", "med", "m"]:
            return "Medium"
        if s in ["5", "6", "notice", "info", "informational", "low", "l"]:
            return "Low"
        if s in ["7", "debug"]:
            return "Informational"
        
        # Capitalize fallback if string
        if s in ["critical", "high", "medium", "low", "informational"]:
            return s.capitalize()
        return "Informational"

    def _normalize_status(self, raw_status: Any, message: str) -> str:
        if raw_status:
            st = str(raw_status).strip().lower()
            if "fail" in st or "deny" in st or "reject" in st:
                return "Failed"
            if "block" in st or "drop" in st:
                return "Blocked"
            if "succ" in st or "allow" in st or "pass" in st or "ok" in st:
                return "Success"
        
        # Infer from message context if status absent
        msg_lower = message.lower()
        if "failed" in msg_lower or "rejected" in msg_lower or "unauthorized" in msg_lower:
            return "Failed"
        if "blocked" in msg_lower or "denied" in msg_lower or "dropped" in msg_lower:
            return "Blocked"
        return "Success"

    def _normalize_timestamp(self, ts: Any) -> str:
        if not ts:
            return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        ts_str = str(ts).strip()
        # Keep ISO format or return standard format
        if "T" in ts_str:
            return ts_str.replace("Z", "").replace("T", " ")[:19]
        return ts_str

    def _safe_int(self, val: Any) -> Optional[int]:
        if val is None or val == "":
            return None
        try:
            return int(val)
        except (ValueError, TypeError):
            return None

    def _infer_source_type(self, source: str, event_type: str) -> str:
        s = f"{source} {event_type}".lower()
        if "firewall" in s or "cef" in s or "port" in s:
            return "Firewall"
        if "auth" in s or "login" in s or "ssh" in s:
            return "Authentication"
        if "linux" in s or "syslog" in s or "kernel" in s:
            return "Linux System"
        if "windows" in s or "event" in s:
            return "Windows Event"
        if "web" in s or "http" in s or "apache" in s or "nginx" in s:
            return "Web Server"
        return "Application"
