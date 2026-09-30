import ipaddress
import re
from datetime import datetime, timezone
from typing import Tuple
from app.models.event import UniversalEvent


class DataCleaningService:
    """
    SIH PS 26156 Data Cleaning Pipeline Stage.
    Detects and repairs invalid fields in normalized event while NEVER modifying the original raw_event.
    """
    def clean_event(self, event: UniversalEvent) -> Tuple[UniversalEvent, int]:
        """
        Cleans normalized event.
        Returns: (cleaned_event, count_of_repaired_fields)
        """
        repaired_count = 0
        notes = list(event.cleaning_notes)

        # 1. Clean & validate Timestamp
        if not event.timestamp or event.timestamp.strip() == "":
            event.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            notes.append("REPAIRED: Missing timestamp populated with ingestion timestamp")
            repaired_count += 1
        else:
            # Check for non-standard timestamp format
            cleaned_ts = event.timestamp.strip()
            if "T" in cleaned_ts:
                cleaned_ts = cleaned_ts.replace("Z", "").replace("T", " ")[:19]
                if cleaned_ts != event.timestamp:
                    event.timestamp = cleaned_ts
                    notes.append("REPAIRED: Timestamp format normalized to YYYY-MM-DD HH:MM:SS")
                    repaired_count += 1

        # 2. Clean & validate Source IP
        if event.src_ip:
            cleaned_ip, repaired = self._validate_and_clean_ip(event.src_ip, "Source IP")
            if repaired:
                notes.append(f"REPAIRED: Source IP '{event.src_ip}' normalized to '{cleaned_ip}'")
                event.src_ip = cleaned_ip
                repaired_count += 1

        # 3. Clean & validate Destination IP
        if event.dst_ip:
            cleaned_ip, repaired = self._validate_and_clean_ip(event.dst_ip, "Destination IP")
            if repaired:
                notes.append(f"REPAIRED: Destination IP '{event.dst_ip}' normalized to '{cleaned_ip}'")
                event.dst_ip = cleaned_ip
                repaired_count += 1

        # 4. Clean & validate Ports
        if event.src_port is not None:
            if not (0 <= event.src_port <= 65535):
                notes.append(f"REPAIRED: Invalid source port {event.src_port} reset to None")
                event.src_port = None
                repaired_count += 1

        if event.dst_port is not None:
            if not (0 <= event.dst_port <= 65535):
                notes.append(f"REPAIRED: Invalid destination port {event.dst_port} reset to None")
                event.dst_port = None
                repaired_count += 1

        # 5. Clean & validate Severity
        valid_severities = {"Critical", "High", "Medium", "Low", "Informational"}
        if event.severity not in valid_severities:
            notes.append(f"REPAIRED: Severity '{event.severity}' mapped to Informational")
            event.severity = "Informational"
            repaired_count += 1

        # 6. Clean & sanitize text fields (trim whitespace)
        if event.username:
            clean_user = event.username.strip().strip("'\"")
            if clean_user != event.username:
                event.username = clean_user
                repaired_count += 1

        if event.message:
            clean_msg = re.sub(r'\s+', ' ', event.message.strip())
            if clean_msg != event.message:
                event.message = clean_msg
                repaired_count += 1

        event.cleaning_notes = notes
        return event, repaired_count

    def _validate_and_clean_ip(self, ip_str: str, field_name: str) -> Tuple[str, bool]:
        clean_ip = ip_str.strip().strip("'\"[]")
        try:
            # Validate using standard ipaddress library
            ip_obj = ipaddress.ip_address(clean_ip)
            return str(ip_obj), (clean_ip != ip_str)
        except ValueError:
            # If invalid IP, sanitize or return fallback 0.0.0.0
            return "0.0.0.0", True
