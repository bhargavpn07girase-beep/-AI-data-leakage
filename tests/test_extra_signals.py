import pytest
from pathlib import Path
from leakguard.extra_signals import (
    check_magic_mismatch,
    compute_shannon_entropy,
    compute_simhash,
    simhash_hamming_distance,
    model_health_mgr,
    burst_detector,
    extract_extra_signals_for_file,
)
from leakguard.api import app
from fastapi.testclient import TestClient

client = TestClient(app)

def test_magic_bytes_mismatch_detection():
    # File named .txt but starting with PDF magic bytes %PDF-
    fake_pdf = Path("test_fake.txt")
    mismatch = check_magic_mismatch(fake_pdf, b"%PDF-1.4 simulated binary header")
    assert mismatch["has_mismatch"] is True
    assert mismatch["actual_type"] == "PDF Document"

    # Legitimate txt file
    normal_txt = Path("test_normal.txt")
    match = check_magic_mismatch(normal_txt, b"Hello world plain text")
    assert match["has_mismatch"] is False

def test_shannon_entropy_calculation():
    zero_entropy = compute_shannon_entropy(b"AAAAAAAAAA")
    assert zero_entropy == 0.0

    high_entropy = compute_shannon_entropy(bytes(range(256)))
    assert high_entropy == 8.0

def test_simhash_near_duplicates():
    tokens1 = ["user", "login", "password", "session", "token", "error"]
    tokens2 = ["user", "login", "password", "session", "token", "warning"]
    tokens3 = ["completely", "different", "article", "biology", "genetics", "plants"]

    h1 = compute_simhash(tokens1)
    h2 = compute_simhash(tokens2)
    h3 = compute_simhash(tokens3)

    dist12 = simhash_hamming_distance(h1, h2)
    dist13 = simhash_hamming_distance(h1, h3)
    assert dist12 < dist13

def test_model_health_and_backup_api():
    res = client.get("/api/model/health")
    assert res.status_code == 200
    data = res.json()
    assert "model_version" in data
    assert "drift_indicator" in data

def test_risk_timeline_api():
    res = client.get("/api/analytics/risk-timeline")
    assert res.status_code == 200
    data = res.json()
    assert "timeline" in data
    assert len(data["timeline"]) == 24
    assert "heatmap" in data
