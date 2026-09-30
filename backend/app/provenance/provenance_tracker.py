import uuid
from datetime import datetime, timezone
from typing import Any, Dict
from app.models.provenance import ProvenanceRecord, StageHistoryItem


class ProvenanceTracker:
    """
    SIH PS 26156 Provenance Audit Tracker.
    Maintains full chain of custody and lineage tracking from raw log entry to normalized event.
    """
    def create_provenance(
        self,
        event_id: str,
        raw_hash: str,
        parser_name: str,
        parser_version: str,
        detected_format: str,
        source: str
    ) -> ProvenanceRecord:
        provenance_id = f"prov-{uuid.uuid4().hex[:12]}"
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        initial_stages = [
            StageHistoryItem(stage="INGESTED", status="complete", timestamp=now_str, details={"source": source}),
            StageHistoryItem(stage="FORMAT_DETECTED", status="complete", timestamp=now_str, details={"detected_format": detected_format}),
            StageHistoryItem(stage="PARSED", status="complete", timestamp=now_str, details={"parser": parser_name, "version": parser_version}),
            StageHistoryItem(stage="NORMALIZED", status="complete", timestamp=now_str, details={"schema": "Universal Schema 1.0.0"}),
        ]

        return ProvenanceRecord(
            provenance_id=provenance_id,
            event_id=event_id,
            raw_hash=raw_hash,
            parser=parser_name,
            parser_version=parser_version,
            normalization_version="1.0.0",
            source=source,
            detected_format=detected_format,
            processing_timestamp=now_str,
            stages=initial_stages,
            validation_result={},
        )

    def record_stage(self, record: ProvenanceRecord, stage_name: str, details: Dict[str, Any] = None) -> ProvenanceRecord:
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        record.stages.append(
            StageHistoryItem(
                stage=stage_name,
                status="complete",
                timestamp=now_str,
                details=details or {}
            )
        )
        return record
