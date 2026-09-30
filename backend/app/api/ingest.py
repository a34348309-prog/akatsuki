from typing import List, Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session
from app.models.pipeline import IngestRequest, ProcessResponse
from app.services.demo_data_service import DemoDataService
from app.services.pipeline_service import PipelineService
from app.storage.database import get_db

router = APIRouter(prefix="/api", tags=["Ingestion & Processing"])
pipeline_service = PipelineService()


@router.post("/ingest", summary="Ingest Raw Log Payload or File")
async def ingest_logs(
    request: Optional[IngestRequest] = None,
    file: Optional[UploadFile] = File(None),
    raw_text: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    """
    Ingest raw logs via JSON request body, multipart form text, or file upload.
    Returns format detection results and initial ingestion metadata.
    """
    logs_to_process: List[str] = []
    source_name = "api_ingest"

    if file:
        source_name = file.filename or "uploaded_file"
        content = await file.read()
        try:
            text_str = content.decode("utf-8")
        except UnicodeDecodeError:
            text_str = content.decode("latin-1", errors="replace")
        logs_to_process = text_str.splitlines()

    elif raw_text:
        logs_to_process = raw_text.splitlines()

    elif request and request.raw_log:
        source_name = request.source_name or "api_ingest"
        logs_to_process = request.raw_log.splitlines()

    if not logs_to_process:
        raise HTTPException(status_code=400, detail="No log payload or file provided.")

    response = pipeline_service.process_raw_logs(db, logs_to_process, source_name=source_name)
    return {
        "status": "success",
        "message": f"Successfully ingested and processed {len(response.events)} log records",
        "result": response
    }


@router.post("/process", response_model=ProcessResponse, summary="Process Logs Through Pipeline")
async def process_logs(
    request: Optional[IngestRequest] = None,
    file: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db)
):
    """
    Run raw log records through the complete 8-stage pre-processing pipeline:
    INGEST → DETECT → PARSE → NORMALIZE → CLEAN → DEDUPLICATE → VALIDATE → STORE & AUDIT.
    """
    logs_to_process: List[str] = []
    source_name = "pipeline_process"

    if file:
        source_name = file.filename or "uploaded_file"
        content = await file.read()
        try:
            text_str = content.decode("utf-8")
        except UnicodeDecodeError:
            text_str = content.decode("latin-1", errors="replace")
        logs_to_process = text_str.splitlines()

    elif request and request.raw_log:
        source_name = request.source_name or "pipeline_process"
        logs_to_process = request.raw_log.splitlines()

    if not logs_to_process:
        raise HTTPException(status_code=400, detail="No log content provided for processing.")

    return pipeline_service.process_raw_logs(db, logs_to_process, source_name=source_name)


@router.post("/process/demo", response_model=ProcessResponse, summary="Run Demo Pipeline on Mixed Logs")
def process_demo(db: Session = Depends(get_db)):
    """
    Loads realistic mixed logs containing Syslog, JSON, CEF, LEEF, and CSV formats.
    Produces deterministic, reproducible results for SIH judge evaluation.
    """
    demo_logs = DemoDataService.get_demo_logs()
    return pipeline_service.process_raw_logs(db, demo_logs, source_name="SIH Demo Logs")
