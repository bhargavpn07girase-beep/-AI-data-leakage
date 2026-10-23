# SentinelDLP UI Action Matrix

This document tracks every interactive control in SentinelDLP, detailing the page, UI label, frontend handler function, backend endpoint, expected behavior, and automated test coverage.

| Page | Control Label / Element | Frontend Handler | Backend Endpoint | Expected Result | Automated Test / Verification |
|---|---|---|---|---|---|
| **Global / Top Bar** | Search Input (`Ctrl+K`) | `openCommandPalette()` / `filterGlobalSearch()` | Client-side filter / navigation | Opens modal; searches incidents & pages | `test_enterprise_platform.py` |
| **Global / Top Bar** | Workspace Folder Dropdown | `handleWorkspaceSelect()` | `GET /api/status` | Displays watched folder path and options | `test_api.py::test_status_endpoint` |
| **Global / Top Bar** | Source Filter Dropdown | `handleSourceFilter()` | `GET /api/incidents?source=...` | Re-queries and filters incident list by source | `test_phase0_fixes.py::test_incident_assignment_and_source_fields` |
| **Global / Top Bar** | Time Range Filter Dropdown | `handleTimeRangeFilter()` | `GET /api/incidents?time_range=...` | Filters events by 1h, 24h, 7d, 30d | `test_phase0_fixes.py::test_incident_assignment_and_source_fields` |
| **Global / Top Bar** | Theme Toggle (Sun/Moon) | `toggleTheme()` | LocalStorage persistence | Switches dark/light CSS variables | `web/app.js::initTheme` |
| **Global / Top Bar** | Language Selector | `setLanguage()` | Local dictionary (`en`/`hi`) | Translates UI labels instantly | `web/app.js::setLanguage` |
| **Global / Top Bar** | Refresh Data Button | `refreshCurrentPage()` | `GET /api/overview` / `GET /api/incidents` | Forces fresh fetch of active view data | `test_overview_and_assistant.py` |
| **Global / Top Bar** | Export View Button | `exportCurrentView()` | `GET /api/incidents` (CSV client/server) | Downloads CSV report of current table | `test_phase0_fixes.py::test_api_audit_pagination_and_export` |
| **Global / Top Bar** | Notification Bell | `toggleNotificationDropdown()` | In-memory / Recent SSE events | Shows unread high/critical incidents | `test_api.py::test_overview_kpis` |
| **Global / Sidebar** | Navigation Items | `switchPage(targetPage)` | Dynamic page view change | Activates section container; updates URL hash | `web/app.js::switchPage` |
| **Global / Sidebar** | Sidebar Collapse Chevron | `toggleSidebarCollapse()` | LocalStorage persistence | Collapses sidebar to icon rail | `web/app.js::toggleSidebarCollapse` |
| **Overview** | Refresh KPI Cards | `loadOverviewData()` | `GET /api/overview` | Updates all KPI counters and definitions | `test_overview_and_assistant.py` |
| **Overview** | Reset Layout Button | `resetWidgetLayout()` | LocalStorage layout reset | Restores default 12-widget grid layout | `web/app.js::resetWidgetLayout` |
| **Overview** | Add Widget Button | `openWidgetGallery()` | Client-side modal | Toggles visibility of dashboard widgets | `web/app.js::openWidgetGallery` |
| **Overview** | Violations Card "View" | `jumpToIncidents(severity)` | `GET /api/incidents?min_risk=...` | Navigates to Incidents filtered by severity | `test_phase0_fixes.py::test_api_incidents_pagination_and_bulk_action` |
| **Overview** | Threat Map Tab Switch | `switchThreatMapTab(tab)` | Client-side tab toggle | Toggles Real-time Scans vs Historical Audits | `web/app.js::switchThreatMapTab` |
| **Overview** | Threat Radar Row Click | `openIncidentDrawer(id)` | `GET /api/incidents/{id}` | Opens slide-in file detail drawer | `test_api.py::test_get_incident_detail` |
| **Overview** | Inline Assignee Select | `updateAssignee(id, name)` | `POST /api/incidents/{id}/action` | Persists assigned analyst to DB | `test_phase0_fixes.py::test_incident_assignment_and_source_fields` |
| **Incidents** | Status / Risk Filter | `filterIncidents()` | `GET /api/incidents?status=...` | Server-side filtered incident query | `test_phase0_fixes.py::test_api_incidents_pagination_and_bulk_action` |
| **Incidents** | Search Bar | `debounceIncidentSearch()` | `GET /api/incidents?search=...` | Substring match on file path & reasons | `test_phase0_fixes.py::test_api_incidents_pagination_and_bulk_action` |
| **Incidents** | Pagination Prev / Next | `changeIncidentPage(dir)` | `GET /api/incidents?page=...` | Fetches target page items | `test_phase0_fixes.py::test_api_incidents_pagination_and_bulk_action` |
| **Incidents** | Select All / Row Checkbox | `toggleSelectAllIncidents()` | Client-side selection state | Updates selection count in bulk bar | `web/app.js::toggleSelectAllIncidents` |
| **Incidents** | Bulk Quarantine Button | `bulkAction("quarantine")` | `POST /api/incidents/bulk-action` | Isolates all selected items to vault | `test_phase0_fixes.py::test_api_incidents_pagination_and_bulk_action` |
| **Incidents** | Bulk Dismiss Button | `bulkAction("dismiss")` | `POST /api/incidents/bulk-action` | Marks all selected items as normal | `test_phase0_fixes.py::test_api_incidents_pagination_and_bulk_action` |
| **Incidents** | Bulk Assign Button | `bulkAction("assign")` | `POST /api/incidents/bulk-action` | Assigns selected items to chosen analyst | `test_phase0_fixes.py::test_incident_assignment_and_source_fields` |
| **Incidents / Drawer** | Quarantine File Button | `quarantineIncident(id)` | `POST /api/incidents/{id}/action` | Moves file to quarantine; updates status | `test_phase0_fixes.py::test_api_incidents_pagination_and_bulk_action` |
| **Incidents / Drawer** | Dismiss Incident Button | `dismissIncident(id)` | `POST /api/incidents/{id}/action` | Marks file as normal; updates status | `test_phase0_fixes.py::test_api_incidents_pagination_and_bulk_action` |
| **Incidents / Drawer** | Restore Incident Button | `restoreIncident(id)` | `POST /api/incidents/{id}/action` | Restores file from quarantine to monitored | `test_phase0_fixes.py::test_quarantine_restore_collision_and_hash` |
| **Incidents / Drawer** | Copy SHA-256 Button | `copyToClipboard(hash)` | Clipboard API | Copies file checksum to system clipboard | `web/app.js::copyToClipboard` |
| **Incidents / Drawer** | Close Drawer (Done/Esc) | `closeDrawer()` | DOM state update | Closes the slide-in drawer | `web/app.js::closeDrawer` |
| **Quarantine** | Restore Item Button | `restoreQuarantinedFile(name)`| `POST /api/quarantine/restore` | Moves file out of vault; marks released | `test_phase0_fixes.py::test_quarantine_restore_collision_and_hash` |
| **Quarantine** | Delete Item Button | `deleteQuarantinedFile(name)` | `DELETE /api/quarantine/{name}` | Purges file from disk; marks purged | `test_phase0_fixes.py::test_quarantine_deletion_syncs_incident_status` |
| **Audit Trail** | Action Filter Dropdown | `filterAuditLog()` | `GET /api/audit?action=...` | Filters audit entries by action | `test_phase0_fixes.py::test_api_audit_pagination_and_export` |
| **Audit Trail** | Export CSV Button | `exportAuditCsv()` | `GET /api/audit/export` | Streams full/filtered audit CSV | `test_phase0_fixes.py::test_api_audit_pagination_and_export` |
| **Upload Review** | Drag-and-Drop Dropzone | `handleDropFiles(e)` | Client-side file buffer queue | Enqueues single/multiple files & folders | `test_enterprise_platform.py::test_batch_upload_up_to_100_files` |
| **Upload Review** | Start Scan Button | `submitBatchUpload()` | `POST /api/upload/batch` | Concurrently evaluates files offline | `test_enterprise_platform.py::test_batch_upload_up_to_100_files` |
| **Upload Review** | Clear Completed Button | `clearUploadQueue()` | Client-side queue reset | Removes finished files from queue | `web/app.js::clearUploadQueue` |
| **Prompt Security** | Textarea Live Verify | `debounceVerifyPrompt()` | `POST /api/prompt/verify` | Returns verdict, score, sanitized text | `test_prompt_verify.py` |
| **Prompt Security** | Copy Sanitized Prompt | `copySanitizedPrompt()` | Clipboard API | Copies redacted prompt text | `web/app.js::copySanitizedPrompt` |
| **Prompt Security** | Check Anomaly Tab | `checkPromptAnomaly()` | `POST /api/prompt/anomaly` | Evaluates jailbreaks, exfiltration, evasion | `test_prompt_anomaly.py` |
| **Prompt Security** | Sample Prompt Buttons | `insertPromptSample(type)` | DOM textarea insertion | Injects preset test prompts | `web/app.js::insertPromptSample` |
| **Policy & Settings**| Range Sliders | `updateSliderBubble(e)` | Real-time DOM value bubble | Updates value label on slider drag | `web/app.js::updateSliderBubble` |
| **Policy & Settings**| Save Policy Changes | `saveSettings()` | `POST /api/settings` | Persists thresholds & toggles to DB | `test_stage5.py` |
| **Policy & Settings**| Run Self-Test Button | `runSelfTest()` | `POST /api/system/self-test` | Runs 6-step end-to-end diagnostic | `test_phase0_fixes.py::test_system_self_test_endpoint` |
| **AI Copilot** | Floating Launcher Button | `toggleAssistantPanel()` | DOM toggle | Opens draggable AI Copilot drawer | `test_overview_and_assistant.py` |
| **AI Copilot** | Draggable Panel Handle | `initDraggableHandle()` | Pointer event listener | Moves floating chat widget across screen | `web/app.js::initDraggableHandle` |
| **AI Copilot** | Send Message / Enter | `sendAssistantMessage()` | `POST /api/assistant/ask` | Context-grounded offline AI response | `test_overview_and_assistant.py` |
| **AI Copilot** | Quick Chip Prompts | `sendQuickChip(text)` | `POST /api/assistant/ask` | Sends predefined query chip to copilot | `test_overview_and_assistant.py` |
| **Global / Top Bar** | Role Selector Dropdown | `onRoleChange(newRole)` | `POST /api/audit/role-change` | Switches role between Analyst, Admin, Auditor; enforces backend headers & UI permissions | `test_phase11_gap_closing.py::test_role_enforcement_auditor_cannot_mutate`, `test_role_enforcement_analyst_permissions`, `test_role_enforcement_admin_permissions` |
| **Global / Top Bar** | Policy & Settings Gear Button | `switchPage('settings')` | Client-side navigation | Navigates to Policy & Settings (restricted to Admin role) | `test_phase11_gap_closing.py::test_role_enforcement_admin_permissions` |
| **Global / Top Bar** | Lock / Sign Out Button | `lockCurrentSession()` / `unlockSession()` | Client-side session locking | Locks UI behind local passcode modal; prevents unauthorized access | `web/app.js::initLockModal` |
| **Global / Top Bar** | Team Global Filter | `onFilterChange()` | `GET /api/incidents?team=...`, `GET /api/overview?team=...` | Re-queries all widgets and tables filtered by assignee team group | `test_phase11_gap_closing.py::test_team_and_region_filtering` |
| **Global / Top Bar** | Region Global Filter | `onFilterChange()` | `GET /api/incidents?region=...`, `GET /api/overview?region=...` | Re-queries all widgets and tables filtered by watched root directory label | `test_phase11_gap_closing.py::test_team_and_region_filtering` |
| **AI Copilot / Console**| Assistant Disabled Guard | `updateAssistantStatus(ready)` | In-memory status check | Disables chat input and displays banner when workspace/DB is unavailable | `test_overview_and_assistant.py` |
| **Scan Reports** | Secondary Nav Tabs | `switchReportsSubTab(subtab)` | Dynamic subtab switcher | Switches between Dashboard, Engines, Watched Folders, Reports, Workflows | `test_phase11_gap_closing.py::test_engines_catalog_endpoint`, `test_watched_folders_endpoint_and_safety` |
| **Scan Reports** | Engines Catalog Subtab | `loadEnginesCatalog()` | `GET /api/engines` | Displays all 5 detection engines with version chips, hits, and timestamps | `test_phase11_gap_closing.py::test_engines_catalog_endpoint` |
| **Scan Reports** | Watched Folders Subtab | `loadWatchedFoldersList()` | `GET /api/watched-folders` | Lists monitored roots with disk size, file count, and scoped-path safety badges | `test_phase11_gap_closing.py::test_watched_folders_endpoint_and_safety` |
| **Workflows** | Create Workflow Rule Form | `saveWorkflowRule()` | `POST /api/workflows` | Configures automated incident actions (quarantine, dismiss, assign, notify) post-scoring | `test_phase11_gap_closing.py::test_workflows_crud_and_dry_run` |
| **Workflows** | Toggle Workflow Rule Switch | `toggleWorkflowRule(id)` | `PUT /api/workflows/{id}/toggle` | Enables or disables automated workflow rule in SQLite | `test_phase11_gap_closing.py::test_workflows_crud_and_dry_run` |
| **Workflows** | Delete Workflow Rule Button | `deleteWorkflowRule(id)` | `DELETE /api/workflows/{id}` | Deletes workflow rule from database | `test_phase11_gap_closing.py::test_workflows_crud_and_dry_run` |
| **Workflows** | Test Rule (Dry Run) Button | `dryRunCurrentFormRule()` | `POST /api/workflows/test` | Dry-runs condition against recent incidents without modifying records | `test_phase11_gap_closing.py::test_workflows_crud_and_dry_run` |
| **Incidents / Drawer** | Create a Workflow Button | `createWorkflowFromIncident()` | Navigates to Workflows builder | Pre-fills condition field/value based on active incident | `web/app.js::createWorkflowFromIncident` |
| **Incidents / Drawer** | Multi-Engine Scan Status Rows | `openIncidentDrawer(id)` | `GET /api/incidents/{id}` | Displays engine status with colored version chips (green/orange) and hit counts | `test_api.py::test_get_incident_detail` |
| **Global / Footer** | Live Watcher Monitor Pill | `fetchStatus()` | `GET /api/status` | Real-time status indicator (Running, Paused, Error) in bottom status bar | `test_api.py::test_status_endpoint` |

