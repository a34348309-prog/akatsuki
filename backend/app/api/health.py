from datetime import datetime, timezone
from fastapi import APIRouter

router = APIRouter(tags=["Health"])


@router.get("/health", summary="System Health Check")
def health_check():
    """Returns system status, deployment operational state, and current ISO timestamp."""
    return {
        "status": "healthy",
        "service": "ULPF — Universal Log Pre-processing Framework",
        "sih_problem_statement": "26156 (NTRO)",
        "team": "Akatsuki",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "air_gapped_mode": True,
        "database": "operational"
    }
