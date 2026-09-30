from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class StageHistoryItem(BaseModel):
    stage: str = Field(..., description="Pipeline stage name (INGESTED, FORMAT_DETECTED, PARSED, etc.)")
    status: str = Field("complete", description="Status of stage execution")
    timestamp: str = Field(..., description="Timestamp of stage execution")
    details: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Metadata captured during stage execution")


class ProvenanceRecord(BaseModel):
    """
    Complete audit trail and provenance record for a log entry.
    """
    provenance_id: str = Field(..., description="Unique provenance ID (prov-...)")
    event_id: str = Field(..., description="Target Event ID")
    raw_hash: str = Field(..., description="SHA-256 hash of original raw event")
    parser: str = Field(..., description="Selected parser module")
    parser_version: str = Field(..., description="Parser version")
    normalization_version: str = Field("1.0.0", description="Normalization version")
    source: str = Field(..., description="Log source")
    detected_format: str = Field(..., description="Detected log format")
    processing_timestamp: str = Field(..., description="Ingestion/Processing timestamp")
    stages: List[StageHistoryItem] = Field(default_factory=list, description="Chronological stage history")
    validation_result: Dict[str, Any] = Field(default_factory=dict, description="Validation summary and issues")
