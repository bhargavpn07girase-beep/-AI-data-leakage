from __future__ import annotations

import io
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from leakguard.api import app, store, engine
from leakguard.scanning import scan_file, scan_file_chunked
from leakguard.modeling import LeakRiskModel, evaluate_model_pipeline


@pytest.fixture
def client():
    return TestClient(app)


def test_chunked_scanning_cross_boundary_match(tmp_path: Path):
    """Ensure regex pattern spanning across streaming chunk boundaries is caught."""
    # Create text with sensitive pattern positioned near the chunk boundary
    padding = "A" * (256 * 1024 - 10) + " "  # space before boundary
    sensitive_pan = "ABCDE1234F"
    content = padding + sensitive_pan + " more text after boundary..."

    test_file = tmp_path / "cross_boundary.txt"
    test_file.write_text(content, encoding="utf-8")

    result = scan_file_chunked(test_file, chunk_size=256 * 1024, overlap=2048)
    assert not result.skipped
    assert "pan" in result.category_counts
    assert result.category_counts["pan"] >= 1


def test_corrupted_document_handling(tmp_path: Path):
    """Ensure corrupted PDF/DOCX does not crash the server and returns clear error reason."""
    bad_pdf = tmp_path / "corrupted.pdf"
    bad_pdf.write_bytes(b"%PDF-1.4 completely corrupt random binary bytes \x00\xff\xee")

    res = scan_file(bad_pdf)
    assert res.skipped is True
    assert "corrupted_document" in res.reason


def test_large_file_resource_limit(tmp_path: Path):
    """Ensure files exceeding hard security limit receive explicit skipped reason without claiming 0% risk."""
    oversized = tmp_path / "oversized.txt"
    # Test with custom small threshold for fast unit test
    oversized.write_text("Hello " * 1000, encoding="utf-8")

    res = scan_file(oversized, max_size_bytes=500)
    assert res.skipped is True
    assert res.reason == "file_too_large"


def test_batch_upload_up_to_100_files(client: TestClient):
    """Test batch upload endpoint handles multiple files with bounded concurrency."""
    files_to_upload = []
    # Create 20 synthetic files in a batch
    for i in range(20):
        if i == 5:
            content = b'{"email": "leak@confidential.com", "credit_card": "4532 0151 8293 4128"}'
            files_to_upload.append(("files", (f"file_{i}_sensitive.json", content, "application/json")))
        elif i == 10:
            content = b'corrupted pdf data'
            files_to_upload.append(("files", (f"file_{i}_corrupt.pdf", content, "application/pdf")))
        else:
            content = f"Standard routine office document #{i} with team calendar info.".encode("utf-8")
            files_to_upload.append(("files", (f"file_{i}_clean.txt", content, "text/plain")))

    response = client.post("/api/upload/batch", files=files_to_upload)
    assert response.status_code == 200
    data = response.json()

    assert data["total_files"] == 20
    assert "batch_id" in data
    assert len(data["items"]) == 20
    assert data["flagged"] >= 1
    assert data["completed"] >= 15

    # Check persistence in batch history
    history_res = client.get(f"/api/upload/batch/history?batch_id={data['batch_id']}")
    assert history_res.status_code == 200
    assert len(history_res.json()) == 20


def test_model_evaluation_pipeline():
    """Test model benchmark returns precision, recall, F1, and confusion matrix."""
    metrics = evaluate_model_pipeline()
    assert "precision" in metrics
    assert "recall" in metrics
    assert "f1_score" in metrics
    assert "confusion_matrix" in metrics
    assert metrics["evaluation_samples"] == 10
    assert metrics["f1_score"] > 0.6
