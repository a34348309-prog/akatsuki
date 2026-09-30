from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from .event import UniversalEvent
from .provenance import ProvenanceRecord


class IngestRequest(BaseModel):
    raw_log: Optional[str] = Field(None, description="Raw log text (single line or multi-line batch)")
    source_name: Optional[str] = Field("api_ingest", description="Optional source label")


class FormatDetectionResult(BaseModel):
    detected_format: str
    confidence: float
    parser: str
    parser_version: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PipelineStage(BaseModel):
    name: str
    status: str  # "complete", "processing", "pending", "failed"
    processed_count: int = 0


class PipelineStatus(BaseModel):
    status: str  # "operational", "processing", "degraded"
    stages: List[PipelineStage]


class ProcessResponse(BaseModel):
    records_detected: int
    records_processed: int
    unique_records: int
    duplicates_removed: int
    invalid_records: int
    missing_values_repaired: int
    detection: Optional[FormatDetectionResult] = None
    events: List[UniversalEvent] = Field(default_factory=list)
    provenance: List[ProvenanceRecord] = Field(default_factory=list)
