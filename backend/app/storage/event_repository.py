import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session
from app.models.event import RawEventRecord, UniversalEvent
from app.models.provenance import ProvenanceRecord, StageHistoryItem
from app.storage.database import NormalizedEventDB, ProvenanceDB, RawEventDB


class EventRepository:
    """
    Repository for persisting, retrieving, searching, and exporting raw events,
    normalized events, and provenance audit traces.
    """
    def save_raw_event(self, db: Session, raw_record: RawEventRecord) -> RawEventRecord:
        db_raw = RawEventDB(
            event_id=raw_record.event_id,
            event_hash=raw_record.event_hash,
            provenance_id=raw_record.provenance_id,
            raw_event=raw_record.raw_event,
            byte_length=raw_record.byte_length,
            ingestion_timestamp=raw_record.ingestion_timestamp,
        )
        db.merge(db_raw)
        db.commit()
        return raw_record

    def save_normalized_event(self, db: Session, event: UniversalEvent) -> UniversalEvent:
        db_event = NormalizedEventDB(
            event_id=event.event_id,
            timestamp=event.timestamp,
            source=event.source,
            source_type=event.source_type,
            vendor=event.vendor,
            event_type=event.event_type,
            category=event.category,
            severity=event.severity,
            src_ip=event.src_ip,
            src_port=event.src_port,
            dst_ip=event.dst_ip,
            dst_port=event.dst_port,
            protocol=event.protocol,
            username=event.username,
            hostname=event.hostname,
            action=event.action,
            status=event.status,
            message=event.message,
            raw_event=event.raw_event,
            parser=event.parser,
            parser_version=event.parser_version,
            normalization_version=event.normalization_version,
            event_hash=event.event_hash,
            provenance_id=event.provenance_id,
            source_fields_json=json.dumps(event.source_fields),
            cleaning_notes_json=json.dumps(event.cleaning_notes),
            validation_status=event.validation_status,
        )
        db.merge(db_event)
        db.commit()
        return event

    def save_provenance(self, db: Session, provenance: ProvenanceRecord) -> ProvenanceRecord:
        stages_data = [stage.model_dump() for stage in provenance.stages]
        db_prov = ProvenanceDB(
            provenance_id=provenance.provenance_id,
            event_id=provenance.event_id,
            raw_hash=provenance.raw_hash,
            parser=provenance.parser,
            parser_version=provenance.parser_version,
            normalization_version=provenance.normalization_version,
            source=provenance.source,
            detected_format=provenance.detected_format,
            processing_timestamp=provenance.processing_timestamp,
            stages_json=json.dumps(stages_data),
            validation_result_json=json.dumps(provenance.validation_result),
        )
        db.merge(db_prov)
        db.commit()
        return provenance

    def get_event(self, db: Session, event_id: str) -> Optional[UniversalEvent]:
        row = db.query(NormalizedEventDB).filter(NormalizedEventDB.event_id == event_id).first()
        if not row:
            return None
        return self._to_universal_event(row)

    def get_raw_event(self, db: Session, event_id: str) -> Optional[RawEventRecord]:
        row = db.query(RawEventDB).filter(RawEventDB.event_id == event_id).first()
        if not row:
            # Fallback check from normalized event table if raw event table missing entry
            norm = db.query(NormalizedEventDB).filter(NormalizedEventDB.event_id == event_id).first()
            if norm:
                return RawEventRecord(
                    event_id=norm.event_id,
                    event_hash=norm.event_hash,
                    provenance_id=norm.provenance_id,
                    raw_event=norm.raw_event,
                    byte_length=len(norm.raw_event.encode("utf-8")),
                    ingestion_timestamp=norm.timestamp,
                )
            return None
        return RawEventRecord(
            event_id=row.event_id,
            event_hash=row.event_hash,
            provenance_id=row.provenance_id,
            raw_event=row.raw_event,
            byte_length=row.byte_length,
            ingestion_timestamp=row.ingestion_timestamp,
        )

    def get_provenance(self, db: Session, event_id: str) -> Optional[ProvenanceRecord]:
        row = db.query(ProvenanceDB).filter(
            (ProvenanceDB.event_id == event_id) | (ProvenanceDB.provenance_id == event_id)
        ).first()
        if not row:
            return None
        
        stages_raw = json.loads(row.stages_json)
        stages = [StageHistoryItem(**s) for s in stages_raw]
        val_result = json.loads(row.validation_result_json)

        return ProvenanceRecord(
            provenance_id=row.provenance_id,
            event_id=row.event_id,
            raw_hash=row.raw_hash,
            parser=row.parser,
            parser_version=row.parser_version,
            normalization_version=row.normalization_version,
            source=row.source,
            detected_format=row.detected_format,
            processing_timestamp=row.processing_timestamp,
            stages=stages,
            validation_result=val_result,
        )

    def search_events(
        self,
        db: Session,
        severity: Optional[str] = None,
        source: Optional[str] = None,
        vendor: Optional[str] = None,
        event_type: Optional[str] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        username: Optional[str] = None,
        hostname: Optional[str] = None,
        status: Optional[str] = None,
        query: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[UniversalEvent]:
        q = db.query(NormalizedEventDB)

        if severity:
            q = q.filter(NormalizedEventDB.severity.ilike(f"%{severity}%"))
        if source:
            q = q.filter(NormalizedEventDB.source.ilike(f"%{source}%"))
        if vendor:
            q = q.filter(NormalizedEventDB.vendor.ilike(f"%{vendor}%"))
        if event_type:
            q = q.filter(NormalizedEventDB.event_type.ilike(f"%{event_type}%"))
        if src_ip:
            q = q.filter(NormalizedEventDB.src_ip == src_ip)
        if dst_ip:
            q = q.filter(NormalizedEventDB.dst_ip == dst_ip)
        if username:
            q = q.filter(NormalizedEventDB.username.ilike(f"%{username}%"))
        if hostname:
            q = q.filter(NormalizedEventDB.hostname.ilike(f"%{hostname}%"))
        if status:
            q = q.filter(NormalizedEventDB.status.ilike(f"%{status}%"))

        if query:
            search_pattern = f"%{query}%"
            q = q.filter(
                (NormalizedEventDB.message.ilike(search_pattern)) |
                (NormalizedEventDB.raw_event.ilike(search_pattern)) |
                (NormalizedEventDB.src_ip.ilike(search_pattern)) |
                (NormalizedEventDB.dst_ip.ilike(search_pattern)) |
                (NormalizedEventDB.username.ilike(search_pattern)) |
                (NormalizedEventDB.event_type.ilike(search_pattern)) |
                (NormalizedEventDB.source.ilike(search_pattern))
            )

        rows = q.order_by(NormalizedEventDB.timestamp.desc()).offset(offset).limit(limit).all()
        return [self._to_universal_event(row) for row in rows]

    def count_events(self, db: Session) -> int:
        return db.query(NormalizedEventDB).count()

    def get_all_events(self, db: Session, limit: int = 1000) -> List[UniversalEvent]:
        rows = db.query(NormalizedEventDB).order_by(NormalizedEventDB.timestamp.desc()).limit(limit).all()
        return [self._to_universal_event(row) for row in rows]

    def _to_universal_event(self, row: NormalizedEventDB) -> UniversalEvent:
        return UniversalEvent(
            event_id=row.event_id,
            timestamp=row.timestamp,
            source=row.source,
            source_type=row.source_type,
            vendor=row.vendor,
            event_type=row.event_type,
            category=row.category,
            severity=row.severity,
            src_ip=row.src_ip,
            src_port=row.src_port,
            dst_ip=row.dst_ip,
            dst_port=row.dst_port,
            protocol=row.protocol,
            username=row.username,
            hostname=row.hostname,
            action=row.action,
            status=row.status,
            message=row.message,
            raw_event=row.raw_event,
            parser=row.parser,
            parser_version=row.parser_version,
            normalization_version=row.normalization_version,
            event_hash=row.event_hash,
            provenance_id=row.provenance_id,
            source_fields=json.loads(row.source_fields_json or "{}"),
            cleaning_notes=json.loads(row.cleaning_notes_json or "[]"),
            validation_status=row.validation_status or "VALID",
        )
