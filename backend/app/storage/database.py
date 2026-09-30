import json
import os
from typing import Any, Dict
from sqlalchemy import Column, Integer, String, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./ulpf_data.db")

# Create SQLite database engine with thread check disabled for SQLite
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class RawEventDB(Base):
    __tablename__ = "raw_events"

    event_id = Column(String(64), primary_key=True, index=True)
    event_hash = Column(String(128), index=True)
    provenance_id = Column(String(64), index=True)
    raw_event = Column(Text, nullable=False)
    byte_length = Column(Integer, nullable=False)
    ingestion_timestamp = Column(String(32), nullable=False)


class NormalizedEventDB(Base):
    __tablename__ = "normalized_events"

    event_id = Column(String(64), primary_key=True, index=True)
    timestamp = Column(String(32), index=True)
    source = Column(String(128), index=True)
    source_type = Column(String(128), index=True)
    vendor = Column(String(128), index=True)
    event_type = Column(String(128), index=True)
    category = Column(String(128), index=True)
    severity = Column(String(32), index=True)
    src_ip = Column(String(64), index=True)
    src_port = Column(Integer, nullable=True)
    dst_ip = Column(String(64), index=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(32), nullable=True)
    username = Column(String(128), index=True)
    hostname = Column(String(128), index=True)
    action = Column(String(64), nullable=True)
    status = Column(String(32), index=True)
    message = Column(Text, nullable=False)
    raw_event = Column(Text, nullable=False)
    parser = Column(String(64), nullable=False)
    parser_version = Column(String(32), nullable=False)
    normalization_version = Column(String(32), nullable=False)
    event_hash = Column(String(128), index=True)
    provenance_id = Column(String(64), index=True)
    source_fields_json = Column(Text, nullable=False, default="{}")
    cleaning_notes_json = Column(Text, nullable=False, default="[]")
    validation_status = Column(String(32), default="VALID")


class ProvenanceDB(Base):
    __tablename__ = "provenance_records"

    provenance_id = Column(String(64), primary_key=True, index=True)
    event_id = Column(String(64), index=True)
    raw_hash = Column(String(128), index=True)
    parser = Column(String(64), nullable=False)
    parser_version = Column(String(32), nullable=False)
    normalization_version = Column(String(32), nullable=False)
    source = Column(String(128), nullable=False)
    detected_format = Column(String(64), nullable=False)
    processing_timestamp = Column(String(32), nullable=False)
    stages_json = Column(Text, nullable=False)
    validation_result_json = Column(Text, nullable=False)


def init_db():
    """Create all database tables on application startup."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """FastAPI Dependency for DB Session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
