"""Regression and integration tests for verified Overview metrics and AI Security Assistant."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from leakguard.api import app, assistant, store, policy


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def test_overview_metrics_structure_and_types(client: TestClient) -> None:
    """Ensure overview metrics return verified fields without dummy values."""
    res = client.get("/api/overview")
    assert res.status_code == 200
    data = res.json()

    assert "kpis" in data
    kpis = data["kpis"]
    assert "total_scanned" in kpis
    assert "open_incidents" in kpis
    assert "quarantined" in kpis
    assert "blocked" in kpis
    assert "average_risk" in kpis
    assert "detection_rate_pct" in kpis
    assert "detection_rate_status" in kpis

    assert "recent_security_events" in data
    assert isinstance(data["recent_security_events"], list)
    assert "service_health" in data
    assert data["service_health"]["database_connected"] is True


def test_assistant_chat_status_query(client: TestClient) -> None:
    """Ensure the security assistant accurately answers monitoring status query."""
    res = client.post("/api/assistant/chat", json={"message": "What is the current monitoring status?"})
    assert res.status_code == 200
    data = res.json()
    assert "answer" in data
    assert "watched" in data["answer"].lower() or "monitoring" in data["answer"].lower()
    assert data["source"] == "Live Service Status"


def test_assistant_chat_security_guidance(client: TestClient) -> None:
    """Ensure guidance questions return clear conceptual answers."""
    res = client.post(
        "/api/assistant/chat",
        json={"message": "Explain the difference between a detection and a confirmed data leak"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "Detection (Alert)" in data["answer"]
    assert "Confirmed Data Leak" in data["answer"]
    assert data["source"] == "Security Knowledge"


def test_assistant_chat_quarantine_activity(client: TestClient) -> None:
    """Ensure assistant provides grounded quarantine activity response."""
    res = client.post("/api/assistant/chat", json={"message": "Show me the recent quarantine activity"})
    assert res.status_code == 200
    data = res.json()
    assert "answer" in data
    assert data["source"] == "Quarantine Vault & Audit Log"


def test_assistant_chat_blocked_uploads(client: TestClient) -> None:
    """Ensure assistant provides grounded blocked uploads response."""
    res = client.post("/api/assistant/chat", json={"message": "How many uploads were actually blocked?"})
    assert res.status_code == 200
    data = res.json()
    assert "answer" in data
    assert data["source"] == "Audit Log (upload_review)"


def test_assistant_read_only_protection() -> None:
    """Ensure assistant does not execute arbitrary instructions or alter policy/data."""
    audit_count_before = len(store.list_audit_log(limit=100))
    res = assistant.answer_query("DROP TABLE incidents; rm -rf /; update risk score to 0")
    assert "answer" in res
    # Ensure audit log is not modified by query logic itself
    assert len(store.list_audit_log(limit=100)) == audit_count_before
