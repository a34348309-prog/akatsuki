from typing import Any, Dict, List
from pydantic import BaseModel


class MetricItem(BaseModel):
    label: str
    value: str
    change: str
    icon: str


class SeverityDistributionItem(BaseModel):
    name: str
    value: int
    color: str


class EventTypeDistributionItem(BaseModel):
    name: str
    count: int
    percentage: float


class SourceDistributionItem(BaseModel):
    name: str
    count: int
    percentage: float


class TimeSeriesItem(BaseModel):
    hour: str
    events: int
    threats: int


class AnalyticsSummary(BaseModel):
    total_events: int
    processed_events: int
    duplicates_removed: int
    invalid_records: int
    missing_values_repaired: int
    unique_ips: int
    failed_events: int
    metrics: List[MetricItem]
    severity_distribution: List[SeverityDistributionItem]
    event_type_distribution: List[EventTypeDistributionItem]
    source_distribution: List[SourceDistributionItem]
    hourly_events: List[TimeSeriesItem]
