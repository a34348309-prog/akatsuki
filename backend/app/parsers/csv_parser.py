import csv
import io
from typing import Any, Dict
from .base import BaseParser


class CSVParser(BaseParser):
    name = "csv"
    version = "1.0.0"
    supported_format = "CSV"

    def can_parse(self, raw_log: str) -> float:
        log_str = raw_log.strip()
        # Should contain commas or tabs without JSON brackets or CEF header
        if any(prefix in log_str for prefix in ["CEF:", "LEEF:", "<", "{"]):
            return 0.0
        comma_count = log_str.count(",")
        tab_count = log_str.count("\t")
        if comma_count >= 3 or tab_count >= 3:
            return 0.80
        return 0.0

    def parse(self, raw_log: str) -> Dict[str, Any]:
        log_str = raw_log.strip()
        delimiter = "\t" if "\t" in log_str and "," not in log_str else ","
        
        try:
            reader = csv.reader(io.StringIO(log_str), delimiter=delimiter)
            row = next(reader)
            if not row:
                return {"raw_event": raw_log, "message": log_str, "source": "csv"}

            # Map based on standard column headers or positional fallback
            # Positional fallback: timestamp, src_ip, dst_ip, username, event_type, status, severity, source, message
            result: Dict[str, Any] = {
                "raw_event": raw_log,
                "vendor": "CSV Log Source",
                "source": "CSV Ingest",
            }

            field_names = ["timestamp", "src_ip", "dst_ip", "username", "event_type", "status", "severity", "source", "message"]
            for idx, val in enumerate(row):
                if idx < len(field_names):
                    result[field_names[idx]] = val.strip()
                else:
                    result[f"col_{idx}"] = val.strip()

            if "message" not in result or not result["message"]:
                result["message"] = f"CSV event record with {len(row)} fields"

            return result
        except Exception:
            return {
                "raw_event": raw_log,
                "message": log_str,
                "source": "csv",
                "vendor": "CSV Log Source",
            }
