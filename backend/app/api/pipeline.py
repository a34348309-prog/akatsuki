from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.models.pipeline import PipelineStage, PipelineStatus
from app.storage.database import get_db
from app.storage.event_repository import EventRepository

router = APIRouter(prefix="/api", tags=["Pipeline Status"])
repository = EventRepository()


@router.get("/pipeline/status", response_model=PipelineStatus, summary="Get Processing Pipeline Stage Status")
def get_pipeline_status(db: Session = Depends(get_db)):
    """
    Exposes operational status and metrics for each processing stage in the framework:
    Ingestion → Format Detection → Parsing → Normalization → Data Cleaning → Deduplication → Validation.
    """
    processed_count = repository.count_events(db)
    
    stages = [
        PipelineStage(name="Ingestion", status="complete", processed_count=processed_count),
        PipelineStage(name="Format Detection", status="complete", processed_count=processed_count),
        PipelineStage(name="Parsing", status="complete", processed_count=processed_count),
        PipelineStage(name="Normalization", status="complete", processed_count=processed_count),
        PipelineStage(name="Data Cleaning", status="complete", processed_count=processed_count),
        PipelineStage(name="Deduplication", status="complete", processed_count=processed_count),
        PipelineStage(name="Validation", status="complete", processed_count=processed_count),
    ]

    return PipelineStatus(
        status="operational",
        stages=stages
    )
