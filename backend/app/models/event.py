from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, computed_field


class UniversalEvent(BaseModel):
    """
    SIH PS 26156 Universal Event Schema
    Common event taxonomy across all heterogeneous log formats.
    """
    event_id: str = Field(..., description="Unique Event Identifier (UUID or prefix)")
    timestamp: str = Field(..., description="Normalized ISO8601 UTC timestamp")
    source: str = Field(..., description="Log source device, service or facility")
    source_type: str = Field("Generic Log", description="Log category / system type")
    vendor: str = Field("Generic", description="Device / software vendor name")
    event_type: str = Field("Security Event", description="Normalized event type/signature")
    category: str = Field("Audit", description="Top-level security category")
    severity: str = Field("Informational", description="Standardized severity: Critical, High, Medium, Low, Informational")
    src_ip: Optional[str] = Field(None, description="Source IP address")
    src_port: Optional[int] = Field(None, description="Source port number")
    dst_ip: Optional[str] = Field(None, description="Destination IP address")
    dst_port: Optional[int] = Field(None, description="Destination port number")
    protocol: Optional[str] = Field(None, description="Network / application protocol")
    username: Optional[str] = Field(None, description="Associated user identity")
    hostname: Optional[str] = Field(None, description="Host identifier / FQDN")
    action: Optional[str] = Field(None, description="Action taken (allow, deny, block, etc.)")
    status: str = Field("Success", description="Outcome status: Success, Failed, Blocked")
    message: str = Field("", description="Human-readable event message")
    
    # Lossless raw event preservation & traceability fields
    raw_event: str = Field(..., description="Byte-for-byte exact original log entry")
    parser: str = Field(..., description="Name of parser module utilized")
    parser_version: str = Field("1.0.0", description="Parser software version")
    normalization_version: str = Field("1.0.0", description="Universal Schema normalization version")
    event_hash: str = Field(..., description="SHA-256 hash of original raw_event (sha256:...)")
    provenance_id: str = Field(..., description="Unique provenance audit trail identifier (prov-...)")
    
    # Preservation of non-standard / vendor-specific fields
    source_fields: Dict[str, Any] = Field(default_factory=dict, description="Lossless store for unmapped source-specific attributes")
    
    # Pipeline quality metadata
    cleaning_notes: List[str] = Field(default_factory=list, description="Audit notes recorded during data cleaning")
    validation_status: str = Field("VALID", description="Validation status: VALID, WARNING, INVALID")

    # Dynamic computed fields for seamless frontend UI binding
    @computed_field
    @property
    def id(self) -> str:
        return self.event_id

    @computed_field
    @property
    def ip(self) -> str:
        return self.src_ip or "0.0.0.0"

    @computed_field
    @property
    def destination(self) -> str:
        return self.dst_ip or "0.0.0.0"

    @computed_field
    @property
    def event(self) -> str:
        return self.event_type


class EventResponse(UniversalEvent):
    """Event model response alias matching Universal Event Schema."""
    pass


class RawEventRecord(BaseModel):
    """Raw Event evidence record model."""
    event_id: str
    event_hash: str
    provenance_id: str
    raw_event: str
    byte_length: int
    ingestion_timestamp: str
