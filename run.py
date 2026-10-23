"""Single-command application entry point for SentinelDLP."""

from __future__ import annotations

import os
import sys
import time
import webbrowser
from pathlib import Path
import uvicorn

# Ensure src/ is in Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))


def main() -> None:
    print("==========================================================")
    print(" [SentinelDLP] AI Data Leakage Prevention & Monitoring")
    print("==========================================================")


    monitored_dir = Path("data/monitored")
    quarantine_dir = Path("data/quarantine")
    monitored_dir.mkdir(parents=True, exist_ok=True)
    quarantine_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Watched Folder: {monitored_dir.resolve()}")
    print(f"[*] Quarantine Vault: {quarantine_dir.resolve()}")
    print("[*] Launching API Server & Web SOC Dashboard on http://localhost:8000")
    print("Press Ctrl+C to terminate SentinelDLP.")
    print("----------------------------------------------------------")

    # Auto-open browser after 1.5 seconds
    def open_browser():
        time.sleep(1.5)
        webbrowser.open("http://localhost:8000")

    import threading
    threading.Thread(target=open_browser, daemon=True).start()

    uvicorn.run("leakguard.api:app", host="0.0.0.0", port=8000, log_level="info")


if __name__ == "__main__":
    main()
