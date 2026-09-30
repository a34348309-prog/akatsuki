import csv
import io
import json
from typing import Optional
from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session
from app.services.demo_data_service import DemoDataService
from app.services.pipeline_service import PipelineService
from app.storage.database import get_db
from app.storage.event_repository import EventRepository

router = APIRouter(prefix="/api/export", tags=["Export"])
repository = EventRepository()
pipeline_service = PipelineService()


def _get_events(db: Session):
    events = repository.get_all_events(db)
    if not events:
        demo_logs = DemoDataService.get_demo_logs()
        res = pipeline_service.process_raw_logs(db, demo_logs, source_name="SIH Demo Logs")
        events = res.events
    return events


@router.get("/json", summary="Export Normalized Events in JSON Format")
def export_json(
    include_forensics: bool = Query(False, description="Set to true to export forensic package (raw_event + normalized + provenance)"),
    db: Session = Depends(get_db)
):
    """
    Export normalized events in JSON format for SIEM/Data Lake integration.
    Supports forensic export mode containing raw events + normalized attributes + provenance chain.
    """
    events = _get_events(db)
    
    if include_forensics:
        bundle = []
        for evt in events:
            prov = repository.get_provenance(db, evt.event_id)
            bundle.append({
                "normalized_event": evt.model_dump(),
                "raw_event_evidence": {
                    "raw_event": evt.raw_event,
                    "event_hash": evt.event_hash,
                    "provenance_id": evt.provenance_id
                },
                "provenance_audit": prov.model_dump() if prov else None
            })
        content = json.dumps(bundle, indent=2)
        filename = "ulpf_forensic_bundle.json"
    else:
        events_dict = [evt.model_dump() for evt in events]
        content = json.dumps(events_dict, indent=2)
        filename = "ulpf_normalized_events.json"

    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@router.get("/csv", summary="Export Normalized Events in CSV Format")
def export_csv(db: Session = Depends(get_db)):
    """Export normalized security events in standard CSV format."""
    events = _get_events(db)
    
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "Event ID", "Timestamp", "Source IP", "Destination IP", "Username",
        "Event Type", "Message", "Status", "Severity", "Source",
        "Vendor", "Parser", "Event Hash", "Provenance ID"
    ])

    for evt in events:
        writer.writerow([
            evt.event_id, evt.timestamp, evt.src_ip or "", evt.dst_ip or "", evt.username or "",
            evt.event_type, evt.message, evt.status, evt.severity, evt.source,
            evt.vendor, evt.parser, evt.event_hash, evt.provenance_id
        ])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="ulpf_normalized_events.csv"'}
    )


@router.get("/cef", summary="Export Normalized Events in CEF Format")
def export_cef(db: Session = Depends(get_db)):
    """Export normalized events formatted as Common Event Format (CEF) log lines."""
    events = _get_events(db)
    
    cef_lines = []
    for evt in events:
        # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        vendor = evt.vendor or "ULPF"
        product = evt.source or "PreProcessor"
        version = evt.normalization_version or "1.0.0"
        sig_id = evt.event_type.replace(" ", "_")
        name = evt.message or evt.event_type
        sev = evt.severity

        extensions = f"src={evt.src_ip or ''} dst={evt.dst_ip or ''} suser={evt.username or ''} outcome={evt.status} rt={evt.timestamp} msg=\"{evt.message}\" prov={evt.provenance_id}"
        cef_line = f"CEF:0|{vendor}|{product}|{version}|{sig_id}|{name}|{sev}|{extensions}"
        cef_lines.append(cef_line)

    content = "\n".join(cef_lines)
    return Response(
        content=content,
        media_type="text/plain",
        headers={"Content-Disposition": 'attachment; filename="ulpf_normalized_events.cef"'}
    )
