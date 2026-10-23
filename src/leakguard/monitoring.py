"""Real filesystem event monitoring, restricted to one configured directory."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer


DEFAULT_EXTENSIONS = frozenset({".txt", ".csv", ".json", ".jsonl", ".log", ".md", ".pdf", ".docx"})
TEMPORARY_SUFFIXES = (".tmp", ".part", ".partial", ".crdownload", ".download", ".swp", ".ds_store")


@dataclass(frozen=True)
class MonitorConfig:
    directory: Path = Path("data/monitored")
    supported_extensions: frozenset[str] = DEFAULT_EXTENSIONS
    debounce_seconds: float = 0.35
    stability_interval_seconds: float = 0.15
    stability_timeout_seconds: float = 5.0
    duplicate_window_seconds: float = 1.0

    def __post_init__(self) -> None:
        extensions = frozenset(
            extension.lower() if extension.startswith(".") else f".{extension.lower()}"
            for extension in self.supported_extensions
        )
        object.__setattr__(self, "directory", Path(self.directory))
        object.__setattr__(self, "supported_extensions", extensions)
        if not extensions:
            raise ValueError("At least one supported file extension is required")
        if any(value <= 0 for value in (
            self.debounce_seconds,
            self.stability_interval_seconds,
            self.stability_timeout_seconds,
            self.duplicate_window_seconds,
        )):
            raise ValueError("Monitor timing values must be greater than zero")


@dataclass(frozen=True)
class FileEvent:
    event_type: str
    path: str
    previous_path: str | None
    destination_inside: bool
    observed_at: str
    size_bytes: int | None


@dataclass
class _PendingEvent:
    event_type: str
    path: Path
    previous_path: str | None
    destination_inside: bool
    queued_at: float
    last_seen: float


class _ScopedEventHandler(FileSystemEventHandler):
    def __init__(self, service: "MonitoringService") -> None:
        self._service = service

    def on_created(self, event: FileSystemEvent) -> None:
        self._service._receive("created", event.src_path, is_directory=event.is_directory)

    def on_modified(self, event: FileSystemEvent) -> None:
        self._service._receive("modified", event.src_path, is_directory=event.is_directory)

    def on_moved(self, event: FileSystemEvent) -> None:
        self._service._receive(
            "moved",
            event.dest_path,
            source_path=event.src_path,
            is_directory=event.is_directory,
        )


class MonitoringService:
    """Watch a dedicated directory and publish stable file metadata events."""

    def __init__(self, config: MonitorConfig, on_event: Callable[[FileEvent], None]) -> None:
        self.config = config
        self._on_event = on_event
        self._observer: Observer | None = None
        self._worker: threading.Thread | None = None
        self._condition = threading.Condition()
        self._pending: dict[tuple[str, str, str | None], _PendingEvent] = {}
        self._recent: dict[tuple[str, str, str | None], tuple[float, tuple[int, int] | None]] = {}
        self._stopping = False
        self._root: Path | None = None
        self._last_error: str | None = None

    @property
    def is_running(self) -> bool:
        observer_running = self._observer is not None and self._observer.is_alive()
        worker_running = self._worker is not None and self._worker.is_alive()
        return observer_running and worker_running

    @property
    def last_error(self) -> str | None:
        return self._last_error

    @property
    def monitored_directory(self) -> Path | None:
        return self._root

    def start(self) -> None:
        if self.is_running:
            return
        self._last_error = None
        root = self.config.directory.expanduser().resolve()
        if root == Path(root.anchor) or root == Path.home().resolve():
            raise ValueError("Refusing to monitor a filesystem root or the user home directory")
        root.mkdir(parents=True, exist_ok=True)
        if not root.is_dir():
            raise NotADirectoryError(f"Monitor path is not a directory: {root}")

        self._root = root
        self._stopping = False
        self._observer = Observer()
        self._observer.schedule(_ScopedEventHandler(self), str(root), recursive=True)
        self._worker = threading.Thread(target=self._process_events, name="leakguard-events", daemon=True)
        try:
            self._observer.start()
            self._worker.start()
        except Exception as error:
            self._last_error = f"{type(error).__name__}: {error}"
            self.stop()
            raise

    def stop(self) -> None:
        observer = self._observer
        worker = self._worker
        if observer is not None and observer.is_alive():
            observer.stop()
        with self._condition:
            self._stopping = True
            self._pending.clear()
            self._condition.notify_all()
        if observer is not None and observer.is_alive():
            observer.join(timeout=5)
        if worker is not None and worker.is_alive():
            worker.join(timeout=5)
        self._observer = None
        self._worker = None

    def _receive(
        self,
        event_type: str,
        raw_path: str,
        *,
        source_path: str | None = None,
        is_directory: bool = False,
    ) -> None:
        if is_directory or self._root is None:
            return
        try:
            destination = Path(raw_path).resolve(strict=False)
            relative_destination = self._relative_to_root(destination)
            source = Path(source_path).resolve(strict=False) if source_path else None
            relative_source = self._relative_to_root(source) if source else None
        except (OSError, RuntimeError, ValueError):
            return

        event_path = destination if relative_destination is not None else source
        relative_event_path = relative_destination if relative_destination is not None else relative_source
        if event_path is None or relative_event_path is None or not self._is_supported(relative_event_path):
            return

        previous_path = relative_source if relative_destination is not None and event_type == "moved" else None
        if event_type == "moved" and relative_destination is None:
            relative_event_path = relative_source
            event_path = source
        key = (event_type, relative_event_path, previous_path)
        now = time.monotonic()
        with self._condition:
            pending = self._pending.get(key)
            if pending is None:
                self._pending[key] = _PendingEvent(
                    event_type=event_type,
                    path=event_path,
                    previous_path=previous_path,
                    destination_inside=relative_destination is not None,
                    queued_at=now,
                    last_seen=now,
                )
            else:
                pending.path = event_path
                pending.last_seen = now
            self._condition.notify()

    def _relative_to_root(self, path: Path) -> str | None:
        assert self._root is not None
        try:
            return path.relative_to(self._root).as_posix()
        except ValueError:
            return None

    def _is_supported(self, relative_path: str) -> bool:
        name = Path(relative_path).name.lower()
        if name.startswith("~$") or name.endswith(TEMPORARY_SUFFIXES):
            return False
        return Path(name).suffix in self.config.supported_extensions

    def _process_events(self) -> None:
        while True:
            ready: list[tuple[tuple[str, str, str | None], _PendingEvent]] = []
            with self._condition:
                if self._stopping:
                    return
                now = time.monotonic()
                for key, pending in list(self._pending.items()):
                    if now - pending.last_seen >= self.config.debounce_seconds:
                        ready.append((key, self._pending.pop(key)))
                if not ready:
                    self._condition.wait(timeout=min(self.config.debounce_seconds, 0.1))
                    continue
            for key, pending in ready:
                try:
                    self._publish_if_stable(key, pending)
                except Exception as error:
                    self._last_error = f"{type(error).__name__}: {error}"

    def _publish_if_stable(
        self,
        key: tuple[str, str, str | None],
        pending: _PendingEvent,
    ) -> None:
        signature: tuple[int, int] | None = None
        size_bytes: int | None = None
        if pending.destination_inside:
            signature = self._wait_for_stable_file(pending.path)
            if signature is None:
                return
            size_bytes = signature[0]

        now = time.monotonic()
        previous = self._recent.get(key)
        if previous and now - previous[0] <= self.config.duplicate_window_seconds and previous[1] == signature:
            return
        self._recent[key] = (now, signature)

        relative_path = self._relative_to_root(pending.path)
        if relative_path is None:
            return
        event = FileEvent(
            event_type=pending.event_type,
            path=relative_path,
            previous_path=pending.previous_path,
            destination_inside=pending.destination_inside,
            observed_at=datetime.now(timezone.utc).isoformat(),
            size_bytes=size_bytes,
        )
        self._on_event(event)

    def _wait_for_stable_file(self, path: Path) -> tuple[int, int] | None:
        deadline = time.monotonic() + self.config.stability_timeout_seconds
        previous: tuple[int, int] | None = None
        stable_samples = 0
        while time.monotonic() < deadline and not self._stopping:
            try:
                resolved = path.resolve(strict=True)
                if self._root is None or self._relative_to_root(resolved) is None or not resolved.is_file():
                    return None
                stat = resolved.stat()
                current = (stat.st_size, stat.st_mtime_ns)
            except (FileNotFoundError, OSError, RuntimeError):
                return None
            if current == previous:
                stable_samples += 1
                if stable_samples >= 2:
                    return current
            else:
                stable_samples = 0
                previous = current
            time.sleep(self.config.stability_interval_seconds)
        return None


def print_event(event: FileEvent) -> None:
    """Print one machine-readable event without exposing absolute file paths."""
    print(json.dumps(asdict(event), ensure_ascii=True), flush=True)
