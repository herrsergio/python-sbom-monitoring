# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

**Initial setup (interactive wizard):**
```bash
./setup-sbom-monitor.sh
```
Creates `venv-monitor/`, installs `pip-audit` and `cyclonedx-bom`, writes `.sbom-monitor.conf`, and optionally configures a cron job.

**Manual scan:**
```bash
./venv-monitor/bin/python sbom_monitor.py \
  --projects ~/Documents/python \
  --output ~/.sbom-monitor \
  --timeout 30 \
  --workers 4
```

**Create notification config template:**
```bash
./venv-monitor/bin/python sbom_notifications.py \
  --registry ~/.sbom-monitor/sbom-registry.json \
  --create-template
```
Writes `~/.sbom-monitor/notifications.json` with permissions `0600`.

**View results:**
```bash
open ~/.sbom-monitor/report.html
```

## Architecture

There are two Python modules and a shell layer:

### `sbom_monitor.py` — main scanner
`SBOMMonitor` class orchestrates everything:
1. `discover_projects()` — walks `projects_root` looking for dirs containing `.venv/pyvenv.cfg` or `venv/pyvenv.cfg`
2. `process_project()` — called in parallel via `ThreadPoolExecutor`; generates SBOM then runs pip-audit
3. `generate_sbom()` — tries `cyclonedx-bom` first; falls back to `pip list --format json` if not installed in the target venv
4. `detect_changes()` — diffs current vs previous registry; compares vulnerabilities by `(name, id)` tuple (not dict equality) to be robust against field ordering
5. `generate_html_report()` — self-contained HTML with inline CSS
6. `_send_notifications()` — delegates to `sbom_notifications.NotificationManager`

Thread safety: a `threading.Lock` guards writes to `current_registry` and `all_vulnerabilities`.

Logging: `StreamHandler` is only attached when `sys.stdout.isatty()` to prevent duplicate log lines when stdout is redirected by cron.

### `sbom_notifications.py` — alerts
`NotificationManager` supports four channels: email (SMTP), Slack (incoming webhook), generic webhook, macOS native (`osascript`). Can be imported by `sbom_monitor.py` or run standalone as a CLI.

### Shell layer
- `.sbom-monitor.conf` — sourced by `run-sbom-monitor.sh`; `SCRIPT_DIR` self-resolves via `${BASH_SOURCE[0]}` so the project can be moved freely; `PROJECTS_DIR`/`OUTPUT_DIR`/`NOTIFICATIONS_CONFIG` use `~`
- `run-sbom-monitor.sh` — cron wrapper; calls `$VENV_PATH/bin/python` directly (never `source activate`) to avoid cron PATH issues
- `venv-monitor/` — the monitor's own isolated venv; gitignored; NOT one of the projects being scanned

### Output (`~/.sbom-monitor/` by default)
| File | Contents |
|---|---|
| `sbom-registry.json` | Full per-project snapshot (SBOM + vulns + package count) |
| `vulnerabilities.json` | Vulnerabilities only, keyed by project name |
| `report.html` | Visual dashboard |
| `monitor.log` | Append-only log from cron runs |

## Known limitations

`setup-sbom-monitor.sh` writes hardcoded absolute paths into `.sbom-monitor.conf`. After running the wizard, manually update the conf to use `~` for user-data paths and `$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)` for `SCRIPT_DIR` to keep it portable.
