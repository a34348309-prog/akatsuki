import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.storage.database import init_db

# Initialize database tables for testing
init_db()

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["sih_problem_statement"] == "26156 (NTRO)"


def test_list_parsers_endpoint():
    response = client.get("/api/parsers")
    assert response.status_code == 200
    data = response.json()
    assert data["count"] >= 5
    assert "CEF" in data["supported_formats"]


def test_process_demo_endpoint():
    response = client.post("/api/process/demo")
    assert response.status_code == 200
    data = response.json()
    assert data["records_detected"] > 0
    assert data["records_processed"] > 0
    assert "events" in data


def test_get_events_endpoint():
    response = client.get("/api/events")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0

    first_event = data[0]
    event_id = first_event["event_id"]

    # Test detail, raw, and provenance endpoints
    detail_res = client.get(f"/api/events/{event_id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["event_id"] == event_id

    raw_res = client.get(f"/api/events/{event_id}/raw")
    assert raw_res.status_code == 200
    assert "raw_event" in raw_res.json()
    assert raw_res.json()["event_hash"].startswith("sha256:")

    prov_res = client.get(f"/api/events/{event_id}/provenance")
    assert prov_res.status_code == 200
    assert prov_res.json()["event_id"] == event_id


def test_analytics_endpoints():
    res_summary = client.get("/api/analytics/summary")
    assert res_summary.status_code == 200
    assert "metrics" in res_summary.json()

    res_sev = client.get("/api/analytics/severity")
    assert res_sev.status_code == 200

    res_sources = client.get("/api/analytics/sources")
    assert res_sources.status_code == 200

    res_types = client.get("/api/analytics/event-types")
    assert res_types.status_code == 200

    res_stats = client.get("/api/stats")
    assert res_stats.status_code == 200


def test_pipeline_status_endpoint():
    res = client.get("/api/pipeline/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "operational"
    assert len(data["stages"]) == 7


def test_export_endpoints():
    res_json = client.get("/api/export/json")
    assert res_json.status_code == 200
    assert res_json.headers["content-type"] == "application/json"

    res_csv = client.get("/api/export/csv")
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers["content-type"]

    res_cef = client.get("/api/export/cef")
    assert res_cef.status_code == 200
    assert "text/plain" in res_cef.headers["content-type"]
