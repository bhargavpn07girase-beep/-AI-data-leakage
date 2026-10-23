# Changelog

All notable changes to SentinelDLP are documented in this file.

## [2.4.0] - Phase 11: Gap-Closing Enterprise Additions - 2026-10-13

### Added
- **RBAC Role Selector (R3 SOC Analysts / Admin / Auditor)**:
  - Top bar pill selector for `SOC Analyst`, `Admin`, and `Auditor`.
  - Backend enforcement via `X-Role` request header:
    - `Auditor`: Strictly read-only; mutation endpoints (`/api/incidents/{id}/action`, `/api/quarantine/*`, `/api/settings`, `/api/workflows`, etc.) return `403 Forbidden`. Frontend disables all mutation buttons with a tooltip.
    - `SOC Analyst`: Operational permissions to quarantine, dismiss, restore, and delete incidents; administrative routes (`/api/settings`, model retrain, rollback, self-test, workflow configuration) return `403 Forbidden`.
    - `Admin`: Unrestricted full access to all operations, settings, retrain, rollback, and workflow rule builder.
  - Role persistence in `localStorage` (`sentinel_role`).
  - Automatic audit trail logging on role changes via `POST /api/audit/role-change`.
- **Top Bar Settings Gear Icon (R3)**:
  - Quick-access gear icon in header adjacent to theme toggle and profile avatar for Policy & Settings navigation.
- **Session Lock / Sign Out Modal (R1)**:
  - Top bar and profile menu "Lock / Sign Out" control.
  - Modal overlay (`#session-lock-modal`) locking the console behind local passcode verification (passcode / `sentinel` / `1234`).
- **Sentinel AI Copilot Disabled State (R1)**:
  - Dynamic status check of database connection and workspace availability.
  - Chat input automatically disabled with placeholder `"Select a workspace to use Sentinel."` and warning banner when offline; re-enables automatically upon reconnection.
- **Global Filters for Team and Region (R2)**:
  - Global filter dropdowns for `Team` (`Unassigned`, `Me`, `SOC Tier 1`, `SOC Tier 2`, `Incident Response`) and `Region` (`Monitored Root`, `Desktop`, `Downloads`).
  - Integrated into `/api/incidents` and `/api/overview` re-query pipelines, updating all KPI widgets and data grids synchronously.
- **Scan Reports Secondary Navigation (R5)**:
  - Secondary navigation bar with working sub-panes: `Dashboard` (overview findings), `Engines` (detection engines catalog), `Watched Folders` (scoped root paths & disk footprint), `Reports` (past reports archive), `Workflows` (incident automation rules), `Settings`, and `Exit`.
- **Detection Engines Catalog & Multi-Scanning Rows (R4/R5)**:
  - `GET /api/engines` endpoint exposing all 5 detection engines: Regex Pattern Library, Luhn Checksum Validator, Keyword & Secret Classifier, IsolationForest ML Model, and Prompt Guard Verifier.
  - Colored version chips (green for current, orange for stale/untrained), hit counts, operational states, and last-updated timestamps displayed in both the Scan Reports engine panel and the Incident Detail Drawer.
- **Watched Folders Scoped-Path Safety (R5 Disks)**:
  - `GET /api/watched-folders` endpoint auditing folder scopes.
  - Verified sandbox scoping: real-time filesystem watcher strictly confined to `data/monitored/` (`SCOPED_SAFE`), with host directories (`Desktop`, `Downloads`) preserved as out-of-bounds protected (`OUT_OF_BOUNDS_PROTECTED`).
- **Incident Automation Workflows (R4/R5)**:
  - SQLite table `workflow_rules` and pipeline integration executing rules post-scoring in `evaluate_file` (zero modification to scoring formulas).
  - Rule engine supporting conditions (`severity`, `file_type`, `category`, `source`, `risk_score`) and actions (`quarantine`, `dismiss`, `assign`, `notify`, `tag`).
  - Dedicated Workflows Builder page (`#page-workflows`) with rule creation form, toggle switches, delete operations, and dry-run testing tool against recent incidents.
  - "Create a workflow" shortcut links in incident drawer and report header pre-filling rule parameters.
  - Each rule execution writes an immutable row to the audit ledger.
- **Fixed Bottom Status Bar (R5)**:
  - Enterprise footer bar (`.soc-bottom-status-bar`) showing application version (`SentinelDLP v2.4 Enterprise`), active role, scoped root status, offline status indicator, and live watcher monitor pill (`Running` / `Paused` / `Error`).
- **Test Suite**:
  - `tests/test_phase11_gap_closing.py` covering role permissions, audit logging, engines catalog, watched folder scoping, workflow rule CRUD and dry-run testing, and global filtering. Full test suite passing (56 passed in 13.56s).

### Verification Status & Limitations
- **Verified**:
  - All 56 automated pytest tests passed with zero regressions.
  - Zero emojis across all HTML, CSS, and JS codebase (verified with strict Unicode parser).
  - Live Uvicorn HTTP server response verified:
    - Auditor read-only 403 Forbidden enforcement on mutations.
    - SOC Analyst admin-action 403 Forbidden enforcement.
    - Admin full access and settings update.
    - Role change audit trail logging via `POST /api/audit/role-change`.
    - Engines catalog (`/api/engines`) and watched-folder scoping (`/api/watched-folders`).
    - Workflow rule CRUD and dry-run testing (`/api/workflows/test`).
- **Could Not Verify**:
  - Automated headless Playwright browser recording: Playwright requires downloading an external browser driver binary (`playwright-1.57.0-win32_x64.zip`), which is unavailable in this strictly air-gapped offline environment (404/no cloud network). Frontend layouts, modals, and handlers were thoroughly verified via source inspection, DOM element contracts, and API integration tests.

