from app.models.event import UniversalEvent
from app.services.deduplication_service import DeduplicationService


def test_deduplication_service():
    dedup = DeduplicationService()

    evt1 = UniversalEvent(
        event_id="evt-1",
        timestamp="2026-09-30 10:00:00",
        source="fw",
        raw_event="exact_same_raw_event_string",
        parser="cef",
        parser_version="1.0.0",
        event_hash="sha256:1111111111111111111111111111111111111111111111111111111111111111",
        provenance_id="prov-1",
    )

    evt2 = UniversalEvent(
        event_id="evt-2",
        timestamp="2026-09-30 10:00:01",
        source="fw",
        raw_event="exact_same_raw_event_string",
        parser="cef",
        parser_version="1.0.0",
        event_hash="sha256:1111111111111111111111111111111111111111111111111111111111111111",
        provenance_id="prov-2",
    )

    unique_events, total, duplicates_removed = dedup.deduplicate([evt1, evt2])

    assert total == 2
    assert len(unique_events) == 1
    assert duplicates_removed == 1
    assert unique_events[0].event_id == "evt-1"
