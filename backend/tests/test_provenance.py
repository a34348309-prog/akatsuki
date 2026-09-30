from app.provenance.provenance_tracker import ProvenanceTracker


def test_provenance_tracker():
    tracker = ProvenanceTracker()
    prov = tracker.create_provenance(
        event_id="evt-100",
        raw_hash="sha256:abc12345",
        parser_name="json",
        parser_version="1.0.0",
        detected_format="JSON",
        source="unit_test"
    )

    assert prov.provenance_id.startswith("prov-")
    assert prov.event_id == "evt-100"
    assert len(prov.stages) == 4

    # Add stage
    prov = tracker.record_stage(prov, "CLEANED", {"repaired": 1})
    assert len(prov.stages) == 5
    assert prov.stages[-1].stage == "CLEANED"
