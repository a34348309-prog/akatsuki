from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.services.pipeline_service import PipelineService
from app.storage.database import Base


def test_full_pipeline_execution():
    # Setup isolated test database in memory
    engine = create_engine("sqlite:///:memory:")
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSession()

    try:
        pipeline = PipelineService()
        raw_logs = [
            '{"event_id": "EVT-9901", "src_ip": "192.168.1.50", "username": "alice", "event_type": "Login", "message": "User login success", "status": "Success", "severity": "Low"}',
            'CEF:0|Vendor|FW|1.0|100|PortScan|4|src=10.0.0.5 dst=10.0.0.1 suser=bob act=block msg=Port scan blocked',
            '<85>1 2026-09-30T10:42:31Z host sshd 88421 - - Failed password for admin from 192.168.1.24'
        ]

        result = pipeline.process_raw_logs(db, raw_logs, source_name="TestIngest")

        assert result.records_detected == 3
        assert result.records_processed == 3
        assert len(result.events) == 3
        assert len(result.provenance) == 3

        # Verify raw event preservation in saved events
        for evt in result.events:
            assert evt.event_hash.startswith("sha256:")
            assert evt.provenance_id.startswith("prov-")
            assert evt.raw_event != ""
    finally:
        db.close()
