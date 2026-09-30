from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.models.event import EventResponse, RawEventRecord, UniversalEvent
from app.models.provenance import ProvenanceRecord
from app.services.demo_data_service import DemoDataService
from app.services.pipeline_service import PipelineService
from app.storage.database import get_db
from app.storage.event_repository import EventRepository

router = APIRouter(prefix="/api", tags=["Events & Search"])
repository = EventRepository()
pipeline_service = PipelineService()


@router.get("/events", response_model=List[EventResponse], summary="Search and Filter Events")
def get_events(
    severity: Optional[str] = Query(None, description="Filter by severity (Critical, High, Medium, Low, Informational)"),
    source: Optional[str] = Query(None, description="Filter by source name"),
    vendor: Optional[str] = Query(None, description="Filter by vendor"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    src_ip: Optional[str] = Query(None, description="Filter by source IP"),
    dst_ip: Optional[str] = Query(None, description="Filter by destination IP"),
    username: Optional[str] = Query(None, description="Filter by username"),
    hostname: Optional[str] = Query(None, description="Filter by hostname"),
    status: Optional[str] = Query(None, description="Filter by status (Success, Failed, Blocked)"),
    query: Optional[str] = Query(None, description="Free-text search across message, raw log, IPs, usernames"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """
    Unified query interface over normalized events.
    Supports multi-field filtering and free-text search across all ingested formats.
    Auto-populates demo dataset if database is empty on initial query.
    """
    count = repository.count_events(db)
    if count == 0:
        demo_logs = DemoDataService.get_demo_logs()
        pipeline_service.process_raw_logs(db, demo_logs, source_name="SIH Demo Logs")

    events = repository.search_events(
        db,
        severity=severity,
        source=source,
        vendor=vendor,
        event_type=event_type,
        src_ip=src_ip,
        dst_ip=dst_ip,
        username=username,
        hostname=hostname,
        status=status,
        query=query,
        limit=limit,
        offset=offset
    )

    # Wrap in EventResponse to include frontend alias properties
    return [EventResponse(**evt.model_dump()) for evt in events]


@router.get("/events/{event_id}", response_model=EventResponse, summary="Get Event Details")
def get_event_by_id(event_id: str, db: Session = Depends(get_db)):
    """Retrieve full normalized event detail by Event ID."""
    event = repository.get_event(db, event_id)
    if not event:
        raise HTTPException(status_code=404, detail=f"Event '{event_id}' not found.")
    return EventResponse(**event.model_dump())


@router.get("/events/{event_id}/raw", response_model=RawEventRecord, summary="Get Lossless Raw Event Evidence")
def get_raw_event(event_id: str, db: Session = Depends(get_db)):
    """
    CRITICAL SIH REQUIREMENT: Lossless raw event preservation.
    Returns exact original raw log text, byte length, and SHA-256 hash.
    """
    raw_record = repository.get_raw_event(db, event_id)
    if not raw_record:
        raise HTTPException(status_code=404, detail=f"Raw event evidence for '{event_id}' not found.")
    return raw_record


@router.get("/events/{event_id}/provenance", response_model=ProvenanceRecord, summary="Get Event Provenance Audit Trail")
def get_event_provenance(event_id: str, db: Session = Depends(get_db)):
    """
    Returns complete audit trail and stage lineage for a log entry:
    INGESTED → FORMAT_DETECTED → PARSED → NORMALIZED → CLEANED → DEDUPLICATED → VALIDATED.
    """
    prov = repository.get_provenance(db, event_id)
    if not prov:
        raise HTTPException(status_code=404, detail=f"Provenance audit trail for '{event_id}' not found.")
    return prov
