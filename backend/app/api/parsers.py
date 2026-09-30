from fastapi import APIRouter
from app.parsers.registry import default_registry

router = APIRouter(prefix="/api", tags=["Parsers"])


@router.get("/parsers", summary="List Registered Parsers")
def list_parsers():
    """
    Returns list of all active parsers registered in the framework.
    Demonstrates plug-and-play architecture capability.
    """
    parsers = default_registry.list_parsers()
    return {
        "count": len(parsers),
        "supported_formats": [p["supported_format"] for p in parsers],
        "parsers": parsers,
        "plugin_architecture": "Active - Custom parsers can be registered without pipeline modification"
    }
