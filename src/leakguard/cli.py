"""Command-line entry point for Stage 1 filesystem monitoring."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from leakguard.monitoring import MonitorConfig, MonitoringService, print_event


def main() -> int:
    parser = argparse.ArgumentParser(description="Watch one dedicated directory for supported file events.")
    parser.add_argument(
        "--directory",
        type=Path,
        default=Path("data/monitored"),
        help="Dedicated directory to watch (default: data/monitored)",
    )
    arguments = parser.parse_args()
    service = MonitoringService(MonitorConfig(directory=arguments.directory), print_event)
    try:
        service.start()
    except (OSError, ValueError) as error:
        print(f"Monitor failed to start: {type(error).__name__}: {error}", file=sys.stderr)
        return 1

    print(f"Monitoring only: {service.monitored_directory}", flush=True)
    print("Supported types: .txt, .csv. Press Ctrl+C to stop.", flush=True)
    try:
        while service.is_running:
            if service.last_error:
                print(f"Monitor error: {service.last_error}", file=sys.stderr, flush=True)
            time.sleep(0.25)
    except KeyboardInterrupt:
        pass
    finally:
        service.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())