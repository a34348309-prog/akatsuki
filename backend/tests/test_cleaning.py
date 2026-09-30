from app.models.event import UniversalEvent
from app.services.cleaning_service import DataCleaningService


def test_data_cleaning_service():
    cleaner = DataCleaningService()

    # Create event with invalid IP, out-of-range port, and missing timestamp
    event = UniversalEvent(
        event_id="evt-test-1",
        timestamp="",
        source="test",
        raw_event="raw text",
        parser="json",
        parser_version="1.0.0",
        event_hash="sha256:abc",
        provenance_id="prov-1",
        src_ip="999.999.999.999",  # Invalid IPv4
        src_port=999999,           # Out of bounds port (> 65535)
        severity="invalid_sev",
        username=" admin ",
        message=" test message ",
    )

    cleaned_evt, repaired_count = cleaner.clean_event(event)

    assert repaired_count >= 4
    assert cleaned_evt.src_ip == "0.0.0.0"
    assert cleaned_evt.src_port is None
    assert cleaned_evt.severity == "Informational"
    assert cleaned_evt.username == "admin"
    assert cleaned_evt.message == "test message"
    assert len(cleaned_evt.timestamp) > 0
    # Crucial SIH check: raw event preserved intact!
    assert cleaned_evt.raw_event == "raw text"
