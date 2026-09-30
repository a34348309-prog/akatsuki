from typing import Any, Dict, List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.analytics.aggregator import AnalyticsAggregator
from app.models.analytics import AnalyticsSummary
from app.services.demo_data_service import DemoDataService
from app.services.pipeline_service import PipelineService
from app.storage.database import get_db
from app.storage.event_repository import EventRepository

router = APIRouter(prefix="/api", tags=["Analytics & Reporting"])
aggregator = AnalyticsAggregator()
repository = EventRepository()
pipeline_service = PipelineService()


def _ensure_data(db: Session) -> List[Any]:
    events = repository.get_all_events(db)
    if not events:
        demo_logs = DemoDataService.get_demo_logs()
        res = pipeline_service.process_raw_logs(db, demo_logs, source_name="SIH Demo Logs")
        events = res.events
    return events


@router.get("/analytics/summary", response_model=AnalyticsSummary, summary="Analytics KPI Summary")
def get_analytics_summary(db: Session = Depends(get_db)):
    """Return complete aggregated KPI summary for dashboard widgets."""
    events = _ensure_data(db)
    return aggregator.compute_analytics(events)


@router.get("/analytics/severity", summary="Severity Distribution Breakdown")
def get_severity_analytics(db: Session = Depends(get_db)):
    """Return distribution of events by severity level."""
    summary = get_analytics_summary(db)
    return {
        "total_events": summary.processed_events,
        "distribution": summary.severity_distribution
    }


@router.get("/analytics/sources", summary="Sources Distribution Breakdown")
def get_source_analytics(db: Session = Depends(get_db)):
    """Return distribution of events by log source / vendor."""
    summary = get_analytics_summary(db)
    return {
        "total_events": summary.processed_events,
        "distribution": summary.source_distribution
    }


@router.get("/analytics/event-types", summary="Event Types Distribution Breakdown")
def get_event_type_analytics(db: Session = Depends(get_db)):
    """Return distribution of events by category and event signature."""
    summary = get_analytics_summary(db)
    return {
        "total_events": summary.processed_events,
        "distribution": summary.event_type_distribution
    }


@router.get("/stats", summary="Comprehensive Processing Statistics")
def get_stats(db: Session = Depends(get_db)):
    """
    Returns aggregate stats: records detected, processed, duplicates removed,
    invalid records, missing values repaired, unique identities, active sources, failed authentication count.
    """
    summary = get_analytics_summary(db)
    return {
        "status": "active",
        "records_detected": summary.total_events,
        "records_processed": summary.processed_events,
        "duplicates_removed": summary.duplicates_removed,
        "invalid_records": summary.invalid_records,
        "missing_values_repaired": summary.missing_values_repaired,
        "unique_ips": summary.unique_ips,
        "failed_events": summary.failed_events,
        "severity_breakdown": {s.name: s.value for s in summary.severity_distribution},
        "time_series": summary.hourly_events
    }
