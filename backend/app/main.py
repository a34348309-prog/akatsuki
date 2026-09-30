from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api import (
    analytics_router,
    events_router,
    export_router,
    health_router,
    ingest_router,
    parsers_router,
    pipeline_router,
)
from app.services.demo_data_service import DemoDataService
from app.services.pipeline_service import PipelineService
from app.storage.database import SessionLocal, init_db
from app.storage.event_repository import EventRepository


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application startup & shutdown events.
    Initializes SQLite schema and populates initial demo dataset for seamless air-gapped demo.
    """
    init_db()
    
    # Pre-populate demo logs if database is currently empty
    db = SessionLocal()
    try:
        repo = EventRepository()
        if repo.count_events(db) == 0:
            pipeline = PipelineService()
            demo_logs = DemoDataService.get_demo_logs()
            pipeline.process_raw_logs(db, demo_logs, source_name="SIH Demo Logs")
    finally:
        db.close()
        
    yield


app = FastAPI(
    title="ULPF — Universal Log Pre-processing Framework",
    description=(
        "Smart India Hackathon 2026 (Problem Statement: 26156 - NTRO)\n\n"
        "A high-performance, air-gapped framework for log format auto-detection, "
        "plug-and-play parsing, universal security schema normalization, data cleaning, "
        "deterministic deduplication, validation, lossless raw evidence storage, and provenance tracking."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Middleware setup for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include all API Routers
app.include_router(health_router)
app.include_router(parsers_router)
app.include_router(ingest_router)
app.include_router(events_router)
app.include_router(analytics_router)
app.include_router(pipeline_router)
app.include_router(export_router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
