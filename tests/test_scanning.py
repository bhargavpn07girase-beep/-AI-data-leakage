from __future__ import annotations

from pathlib import Path

from leakguard.monitoring import MonitorConfig, MonitoringService
from leakguard.scanning import scan_directory, scan_file


def test_scan_jsonl_masks_sensitive_values(tmp_path: Path) -> None:
    file_path = tmp_path / "sample.jsonl"
    file_path.write_text(
        '{"email": "user@example.com", "phone": "555-123-4567"}\n'
        '{"url": "https://example.com/results", "name": "Jane Doe"}\n',
        encoding="utf-8",
    )

    result = scan_file(file_path)

    assert result.skipped is False
    assert len(result.findings) >= 3
    assert "[EMAIL]" in result.masked_text
    assert "[PHONE]" in result.masked_text
    assert "[URL]" in result.masked_text
    assert "user@example.com" not in result.masked_text


def test_scan_rejects_large_files(tmp_path: Path) -> None:
    file_path = tmp_path / "large.jsonl"
    file_path.write_text("x" * 2000, encoding="utf-8")

    result = scan_file(file_path, max_size_bytes=100)

    assert result.skipped is True
    assert result.reason == "file_too_large"


def test_scan_directory_handles_utf8_replacement(tmp_path: Path) -> None:
    file_path = tmp_path / "mixed.csv"
    file_path.write_bytes(b"name,contact\nAlice,alice@example.com\n")

    results = scan_directory(tmp_path)
    assert len(results) == 1
    assert results[0].findings
    assert "[EMAIL]" in results[0].masked_text


def test_monitor_config_supports_json_filter() -> None:
    config = MonitorConfig(directory="data/monitored")
    assert ".json" in config.supported_extensions
    assert ".jsonl" in config.supported_extensions

    service = MonitoringService(config, lambda event: None)
    assert service.config.supported_extensions == config.supported_extensions
