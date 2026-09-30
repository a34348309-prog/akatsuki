from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from app.models.event import RawEventRecord, UniversalEvent
from app.models.pipeline import FormatDetectionResult, ProcessResponse
from app.models.provenance import ProvenanceRecord
from app.normalization.normalizer import EventNormalizer
from app.parsers.registry import default_registry
from app.provenance.provenance_tracker import ProvenanceTracker
from app.services.cleaning_service import DataCleaningService
from app.services.deduplication_service import DeduplicationService
from app.storage.event_repository import EventRepository
from app.validation.validator import EventValidator


class PipelineService:
    """
    SIH PS 26156 Core Processing Pipeline.
    Orchestrates: INGEST → DETECT → PARSE → NORMALIZE → CLEAN → DEDUPLICATE → VALIDATE → STORE & AUDIT.
    """
    def __init__(self):
        self.parser_registry = default_registry
        self.normalizer = EventNormalizer()
        self.cleaner = DataCleaningService()
        self.deduplicator = DeduplicationService()
        self.validator = EventValidator()
        self.provenance_tracker = ProvenanceTracker()
        self.repository = EventRepository()

    def process_raw_logs(
        self,
        db: Session,
        raw_logs: List[str],
        source_name: str = "Ingest Pipeline"
    ) -> ProcessResponse:
        """
        Process a list of raw log strings through the complete ULPF pipeline.
        """
        records_detected = len(raw_logs)
        processed_events: List[UniversalEvent] = []
        provenance_records: List[ProvenanceRecord] = []
        
        total_repaired_count = 0
        invalid_records_count = 0
        last_detection: Optional[FormatDetectionResult] = None

        for raw_log in raw_logs:
            raw_str = raw_log.strip()
            if not raw_str:
                continue

            # Stage 1 & 2: FORMAT DETECTION
            parser, confidence, detected_format = self.parser_registry.detect_format(raw_str)
            last_detection = FormatDetectionResult(
                detected_format=detected_format,
                confidence=confidence,
                parser=parser.name,
                parser_version=parser.version,
                metadata={"source": source_name}
            )

            # Stage 3: PARSING
            parsed_data = parser.parse(raw_str)

            # Initialize Provenance Tracking
            temp_event_id = parsed_data.get("event_id") or parsed_data.get("id") or "temp"
            provenance = self.provenance_tracker.create_provenance(
                event_id=temp_event_id,
                raw_hash="pending",
                parser_name=parser.name,
                parser_version=parser.version,
                detected_format=detected_format,
                source=source_name
            )

            # Stage 4: NORMALIZATION
            event = self.normalizer.normalize(
                parsed_data=parsed_data,
                parser_name=parser.name,
                parser_version=parser.version,
                raw_log=raw_str,
                provenance_id=provenance.provenance_id
            )
            
            # Update provenance with actual event_id and SHA-256 raw hash
            provenance.event_id = event.event_id
            provenance.raw_hash = event.event_hash

            # Stage 5: DATA CLEANING (Never modifies raw_event)
            event, repaired_count = self.cleaner.clean_event(event)
            total_repaired_count += repaired_count
            provenance = self.provenance_tracker.record_stage(
                provenance,
                "CLEANED",
                {"repaired_fields_count": repaired_count, "notes": event.cleaning_notes}
            )

            # Stage 7: VALIDATION
            status, issues, details = self.validator.validate(event)
            event.validation_status = status
            if status == "INVALID":
                invalid_records_count += 1

            provenance.validation_result = details
            provenance = self.provenance_tracker.record_stage(
                provenance,
                "VALIDATED",
                {"status": status, "issues_count": len(issues)}
            )

            processed_events.append(event)
            provenance_records.append(provenance)

        # Stage 6: DEDUPLICATION (Deterministic raw event hash matching)
        unique_events, total_detected_count, duplicates_removed_count = self.deduplicator.deduplicate(processed_events)

        # Update stage history for deduplication
        for prov in provenance_records:
            self.provenance_tracker.record_stage(
                prov,
                "DEDUPLICATED",
                {"unique_records_kept": len(unique_events), "duplicates_removed": duplicates_removed_count}
            )

        # Stage 8: RAW + NORMALIZED STORAGE & PROVENANCE AUDIT PERSISTENCE
        for event in unique_events:
            raw_record = RawEventRecord(
                event_id=event.event_id,
                event_hash=event.event_hash,
                provenance_id=event.provenance_id,
                raw_event=event.raw_event,
                byte_length=len(event.raw_event.encode("utf-8")),
                ingestion_timestamp=event.timestamp,
            )
            self.repository.save_raw_event(db, raw_record)
            self.repository.save_normalized_event(db, event)

        for prov in provenance_records:
            self.repository.save_provenance(db, prov)

        return ProcessResponse(
            records_detected=records_detected,
            records_processed=len(unique_events),
            unique_records=len(unique_events),
            duplicates_removed=duplicates_removed_count,
            invalid_records=invalid_records_count,
            missing_values_repaired=total_repaired_count,
            detection=last_detection,
            events=unique_events,
            provenance=provenance_records,
        )
