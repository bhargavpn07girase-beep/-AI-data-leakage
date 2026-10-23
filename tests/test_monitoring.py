from __future__ import annotations

import queue
import time
from pathlib import Path

import pytest

from leakguard.monitoring import FileEvent, MonitorConfig, MonitoringService


@pytest.fixture
def event_queue() -> queue.Queue[FileEvent]:
    return queue.Queue()


def make_config(directory: Path) -> MonitorConfig:
    return MonitorConfig(
        directory=directory,
        debounce_seconds=0.12,
        stability_interval_seconds=0.05,
        stability_timeout_seconds=2.0,
        duplicate_window_seconds=0.5,
    )


def wait_for_event(
    events: queue.Queue[FileEvent],
    predicate,
    timeout: float = 5.0,
) -> FileEvent:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            event = events.get(timeout=max(0.01, deadline - time.monotonic()))
        except queue.Empty:
            break
        if predicate(event):
            return event
    raise AssertionError("Expected filesystem event was not observed before timeout")


def test_detects_create_modify_and_move(tmp_path: Path, event_queue: queue.Queue[FileEvent]) -> None:
    service = MonitoringService(make_config(tmp_path / "monitored"), event_queue.put)
    service.start()
    try:
        root = service.monitored_directory
        assert root is not None
        source = root / "notes.txt"
        source.write_text("first write", encoding="utf-8")
        created = wait_for_event(event_queue, lambda event: event.event_type == "created")
        assert created.path == "notes.txt"
        assert created.size_bytes == len("first write")

        source.write_text("second, longer write", encoding="utf-8")
        modified = wait_for_event(event_queue, lambda event: event.event_type == "modified")
        assert modified.path == "notes.txt"
        assert modified.size_bytes == len("second, longer write")

        destination = root / "renamed.csv"
        source.rename(destination)
        moved = wait_for_event(event_queue, lambda event: event.event_type == "moved")
        assert moved.path == "renamed.csv"
        assert moved.previous_path == "notes.txt"
        assert moved.destination_inside is True
    finally:
        service.stop()
    assert service.is_running is False


def test_ignores_unsupported_and_temporary_files(
    tmp_path: Path,
    event_queue: queue.Queue[FileEvent],
) -> None:
    service = MonitoringService(make_config(tmp_path / "monitored"), event_queue.put)
    service.start()
    try:
        root = service.monitored_directory
        assert root is not None
        (root / "program.exe").write_bytes(b"not scanned")
        (root / "upload.txt.part").write_text("incomplete", encoding="utf-8")
        (root / "~$draft.txt").write_text("temporary", encoding="utf-8")
        with pytest.raises(queue.Empty):
            event_queue.get(timeout=0.7)
    finally:
        service.stop()


def test_rejects_filesystem_root() -> None:
    service = MonitoringService(make_config(Path(Path.cwd().anchor)), lambda _: None)
    with pytest.raises(ValueError, match="filesystem root"):
        service.start()
