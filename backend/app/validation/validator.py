from typing import Any, Dict, List, Tuple
from app.models.event import UniversalEvent


class EventValidator:
    """
    SIH PS 26156 Event Validation Stage.
    Validates normalized events against Universal Event Schema specifications.
    """
    def validate(self, event: UniversalEvent) -> Tuple[str, List[str], Dict[str, Any]]:
        """
        Validates a UniversalEvent instance.
        Returns: (status, issues_list, validation_details)
        Status: "VALID", "WARNING", or "INVALID"
        """
        issues: List[str] = []
        checks_performed = 0

        # Check 1: Mandatory Event Identifier
        checks_performed += 1
        if not event.event_id or not event.event_id.strip():
            issues.append("CRITICAL: Missing event_id")

        # Check 2: Raw Event Preservation
        checks_performed += 1
        if not event.raw_event or not event.raw_event.strip():
            issues.append("CRITICAL: Original raw_event missing or empty (Lossless requirement violated)")

        # Check 3: Raw Event Hash
        checks_performed += 1
        if not event.event_hash or not event.event_hash.startswith("sha256:"):
            issues.append("CRITICAL: Missing or invalid SHA-256 event_hash")

        # Check 4: Provenance Traceability ID
        checks_performed += 1
        if not event.provenance_id or not event.provenance_id.startswith("prov-"):
            issues.append("CRITICAL: Missing provenance_id tracking reference")

        # Check 5: Timestamp Presence
        checks_performed += 1
        if not event.timestamp:
            issues.append("WARNING: Missing timestamp")

        # Check 6: Severity taxonomy compliance
        checks_performed += 1
        valid_severities = {"Critical", "High", "Medium", "Low", "Informational"}
        if event.severity not in valid_severities:
            issues.append(f"WARNING: Non-standard severity rating '{event.severity}'")

        # Check 7: Cleaning notes inspection
        checks_performed += 1
        if len(event.cleaning_notes) > 0:
            issues.append(f"NOTE: Event contains {len(event.cleaning_notes)} auto-repaired fields")

        # Determine overall validation status
        has_critical = any("CRITICAL" in issue for issue in issues)
        has_warning = any("WARNING" in issue for issue in issues)

        if has_critical:
            status = "INVALID"
        elif has_warning:
            status = "WARNING"
        else:
            status = "VALID"

        details = {
            "checks_performed": checks_performed,
            "status": status,
            "issues": issues,
            "cleaning_notes_count": len(event.cleaning_notes),
            "unmapped_source_fields_count": len(event.source_fields),
        }

        return status, issues, details
