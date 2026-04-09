#!/usr/bin/env python3
"""
SBOM Monitor: Aggregate SBOMs and track vulnerabilities across all local Python projects.

Features:
- Auto-discovers projects with .venv or venv directories
- Generates CycloneDX SBOMs for each project
- Runs pip-audit to detect vulnerabilities
- Maintains a registry of all dependencies
- Tracks changes and alerts on new/updated vulnerabilities
- Generates HTML report
- Sends notifications via email, Slack, or webhook
"""

import json
import subprocess
import sys
import os
import logging
import threading
import concurrent.futures
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import argparse


def _setup_logging(output_dir: Path) -> logging.Logger:
    """Configure console and file logging."""
    logger = logging.getLogger("sbom_monitor")
    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    log_file = output_dir / "monitor.log"
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger


class SBOMMonitor:
    def __init__(self, projects_root: Path, output_dir: Path, scan_timeout: int = 30):
        self.projects_root = projects_root.expanduser()
        self.output_dir = output_dir.expanduser()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.scan_timeout = scan_timeout

        self.registry_file = self.output_dir / "sbom-registry.json"
        self.vulns_file = self.output_dir / "vulnerabilities.json"
        self.report_file = self.output_dir / "report.html"

        self.logger = _setup_logging(self.output_dir)
        self.previous_registry = self._load_registry()
        self.current_registry: Dict = {}
        self.all_vulnerabilities: Dict = {}
        self._lock = threading.Lock()

    def _load_registry(self) -> Dict:
        """Load previous SBOM registry if it exists."""
        if self.registry_file.exists():
            with open(self.registry_file) as f:
                return json.load(f)
        return {}

    def discover_projects(self) -> List[Path]:
        """Find all projects with .venv or venv directories."""
        projects = []

        if not self.projects_root.exists():
            self.logger.warning("Projects root %s does not exist", self.projects_root)
            return projects

        for item in self.projects_root.iterdir():
            if not item.is_dir():
                continue

            for venv_name in [".venv", "venv"]:
                venv_dir = item / venv_name
                if venv_dir.exists() and (venv_dir / "pyvenv.cfg").exists():
                    projects.append(item)
                    self.logger.info("Found project: %s", item.name)
                    break

        return sorted(projects)

    def get_python_executable(self, project: Path) -> Optional[Path]:
        """Find and validate the Python executable in a project's venv."""
        for venv_name in [".venv", "venv"]:
            venv_path = project / venv_name
            if not venv_path.exists():
                continue

            python = venv_path / "bin" / "python"
            if not python.exists():
                python = venv_path / "Scripts" / "python.exe"
            if not python.exists():
                continue

            # Verify the executable actually runs before returning it
            try:
                result = subprocess.run(
                    [str(python), "--version"],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode == 0:
                    return python
                self.logger.debug("Python at %s returned non-zero for --version", python)
            except Exception as e:
                self.logger.debug("Python health check failed for %s: %s", python, e)

        return None

    def _extract_package_count(self, sbom: Dict) -> int:
        """Extract package count from either CycloneDX or pip-list SBOM format."""
        if sbom.get("method") == "pip-list":
            return len(sbom.get("packages", {}))
        # CycloneDX format stores packages in "components" as a list
        components = sbom.get("components", [])
        if isinstance(components, list):
            return len(components)
        return 0

    def _extract_packages(self, sbom: Dict) -> Dict[str, str]:
        """Extract {name: version} mapping from either SBOM format."""
        if sbom.get("method") == "pip-list":
            return sbom.get("packages", {})
        result = {}
        for comp in sbom.get("components", []):
            name = comp.get("name", "")
            version = comp.get("version", "")
            if name:
                result[name] = version
        return result

    def get_installed_packages(self, python_exe: Path) -> Dict[str, str]:
        """Get installed packages and versions using pip list."""
        try:
            result = subprocess.run(
                [str(python_exe), "-m", "pip", "list", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=self.scan_timeout
            )
            if result.returncode == 0:
                packages = json.loads(result.stdout)
                return {pkg["name"]: pkg["version"] for pkg in packages}
        except Exception as e:
            self.logger.error("Error getting packages: %s", e)
        return {}

    def generate_sbom(self, project: Path, python_exe: Path) -> Optional[Dict]:
        """Generate SBOM using cyclonedx-bom, falling back to pip list."""
        try:
            result = subprocess.run(
                [str(python_exe), "-m", "pip", "show", "cyclonedx-bom"],
                capture_output=True,
                timeout=10
            )

            if result.returncode != 0:
                packages = self.get_installed_packages(python_exe)
                return {
                    "project": project.name,
                    "timestamp": datetime.now().isoformat(),
                    "packages": packages,
                    "method": "pip-list"
                }

            result = subprocess.run(
                [str(python_exe), "-m", "cyclonedx", "pip", "-o", "json"],
                capture_output=True,
                text=True,
                cwd=str(project),
                timeout=self.scan_timeout
            )

            if result.returncode == 0:
                return json.loads(result.stdout)

            packages = self.get_installed_packages(python_exe)
            return {
                "project": project.name,
                "timestamp": datetime.now().isoformat(),
                "packages": packages,
                "method": "pip-list"
            }
        except subprocess.TimeoutExpired:
            self.logger.warning("Timeout generating SBOM for %s", project.name)
        except Exception as e:
            self.logger.error("Error generating SBOM for %s: %s", project.name, e)
        return None

    def scan_vulnerabilities(self, python_exe: Path, project: Path) -> List[Dict]:
        """Run pip-audit to find vulnerabilities."""
        try:
            subprocess.run(
                [str(python_exe), "-m", "pip", "install", "--quiet", "pip-audit"],
                timeout=self.scan_timeout,
                capture_output=True
            )

            result = subprocess.run(
                [str(python_exe), "-m", "pip_audit", "--desc", "--format", "json"],
                capture_output=True,
                text=True,
                cwd=str(project),
                timeout=self.scan_timeout
            )

            if result.returncode in [0, 1]:  # 0 = no vulns, 1 = vulns found
                try:
                    data = json.loads(result.stdout)
                    return data.get("vulnerabilities", [])
                except json.JSONDecodeError:
                    return []
        except subprocess.TimeoutExpired:
            self.logger.warning("Timeout scanning vulnerabilities for %s", project.name)
        except Exception as e:
            self.logger.error("Error scanning vulnerabilities for %s: %s", project.name, e)
        return []

    def process_project(self, project: Path) -> bool:
        """Process a single project: generate SBOM and scan for vulnerabilities."""
        self.logger.info("Processing: %s", project.name)

        python_exe = self.get_python_executable(project)
        if not python_exe:
            self.logger.error("Could not find a working Python executable in %s venv", project.name)
            return False

        self.logger.debug("Generating SBOM for %s", project.name)
        sbom = self.generate_sbom(project, python_exe)
        if not sbom:
            self.logger.error("Failed to generate SBOM for %s", project.name)
            return False

        self.logger.debug("Scanning vulnerabilities for %s", project.name)
        vulns = self.scan_vulnerabilities(python_exe, project)

        if vulns:
            self.logger.warning("Found %d vulnerabilities in %s", len(vulns), project.name)
        else:
            self.logger.info("No vulnerabilities found in %s", project.name)

        entry = {
            "path": str(project),
            "timestamp": datetime.now().isoformat(),
            "sbom": sbom,
            "vulnerabilities": vulns,
            "package_count": self._extract_package_count(sbom)
        }

        with self._lock:
            self.current_registry[project.name] = entry
            if vulns:
                self.all_vulnerabilities[project.name] = vulns

        return True

    def detect_changes(self) -> Dict:
        """Detect what's changed since last run."""
        changes = {
            "new_projects": [],
            "removed_projects": [],
            "new_vulnerabilities": {},
            "added_packages": {},
            "removed_packages": {},
        }

        for project_name in self.current_registry:
            if project_name not in self.previous_registry:
                changes["new_projects"].append(project_name)

        for project_name in self.previous_registry:
            if project_name not in self.current_registry:
                changes["removed_projects"].append(project_name)

        # Compare by (name, id) tuple to be robust against dict key ordering differences
        for project_name, vulns in self.all_vulnerabilities.items():
            prev_vulns = self.previous_registry.get(project_name, {}).get("vulnerabilities", [])
            prev_ids = {
                (v.get("name", ""), v.get("id", v.get("vulnerability_id", "")))
                for v in prev_vulns
            }
            new_vulns = [
                v for v in vulns
                if (v.get("name", ""), v.get("id", v.get("vulnerability_id", ""))) not in prev_ids
            ]
            if new_vulns:
                changes["new_vulnerabilities"][project_name] = new_vulns

        # Dependency diff: added/removed packages per project
        for project_name, data in self.current_registry.items():
            prev_data = self.previous_registry.get(project_name)
            if not prev_data:
                continue
            curr_pkgs = self._extract_packages(data["sbom"])
            prev_pkgs = self._extract_packages(prev_data["sbom"])
            added = {k: v for k, v in curr_pkgs.items() if k not in prev_pkgs}
            removed = {k: v for k, v in prev_pkgs.items() if k not in curr_pkgs}
            if added:
                changes["added_packages"][project_name] = added
            if removed:
                changes["removed_packages"][project_name] = removed

        return changes

    def save_registry(self):
        """Save the current registry to disk."""
        with open(self.registry_file, "w") as f:
            json.dump(self.current_registry, f, indent=2)
        self.logger.info("Registry saved to %s", self.registry_file)

    def save_vulnerabilities(self):
        """Save vulnerability report."""
        with open(self.vulns_file, "w") as f:
            json.dump(self.all_vulnerabilities, f, indent=2)
        self.logger.info("Vulnerabilities saved to %s", self.vulns_file)

    @staticmethod
    def _vuln_sort_key(vuln: Dict) -> str:
        """Sort vulnerabilities: CVEs before GHSAs, then alphabetically by ID."""
        vid = vuln.get("id", vuln.get("vulnerability_id", ""))
        return ("0" if vid.startswith("CVE-") else "1") + vid

    def generate_html_report(self, changes: Dict):
        """Generate an HTML report."""
        total_vulns = sum(len(v) for v in self.all_vulnerabilities.values())
        vuln_card_class = "danger" if total_vulns > 0 else ""

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Python SBOM Monitor Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #0066cc; padding-bottom: 10px; }}
        h2 {{ color: #0066cc; margin-top: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat-card {{ background: #f0f7ff; border-left: 4px solid #0066cc; padding: 15px; border-radius: 4px; }}
        .stat-card.danger {{ background: #ffe6e6; border-left-color: #ff0000; }}
        .stat-number {{ font-size: 28px; font-weight: bold; color: #0066cc; }}
        .stat-card.danger .stat-number {{ color: #ff0000; }}
        .stat-label {{ font-size: 12px; color: #666; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f0f7ff; font-weight: 600; color: #0066cc; }}
        tr:hover {{ background: #f9f9f9; }}
        .timestamp {{ color: #999; font-size: 12px; }}
        .alert {{ background: #fff3cd; border: 1px solid #ffc107; padding: 15px; border-radius: 4px; margin: 15px 0; }}
        .alert.danger {{ background: #ffe6e6; border-color: #ff0000; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 12px; font-size: 12px; margin: 0 4px; }}
        .badge.new {{ background: #d4edda; color: #155724; }}
        .badge.removed {{ background: #e7d4d4; color: #721c24; }}
        .badge.critical {{ background: #ff0000; color: white; }}
        .badge.clean {{ background: #d4edda; color: #155724; }}
        .badge.cve {{ background: #cc0000; color: white; font-family: monospace; font-size: 11px; }}
        .badge.ghsa {{ background: #e67e22; color: white; font-family: monospace; font-size: 11px; }}
        .vulnerability {{ background: #ffe6e6; border-left: 4px solid #ff0000; padding: 12px; margin: 10px 0; border-radius: 4px; }}
        .pkg-diff {{ font-family: monospace; font-size: 12px; padding: 2px 6px; border-radius: 3px; display: inline-block; margin: 2px; }}
        .pkg-added {{ background: #d4edda; color: #155724; }}
        .pkg-removed {{ background: #f8d7da; color: #721c24; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #999; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Python SBOM Monitor Report</h1>
        <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

        <div class="summary">
            <div class="stat-card">
                <div class="stat-number">{len(self.current_registry)}</div>
                <div class="stat-label">Projects Monitored</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{sum(p.get('package_count', 0) for p in self.current_registry.values())}</div>
                <div class="stat-label">Total Dependencies</div>
            </div>
            <div class="stat-card {vuln_card_class}">
                <div class="stat-number">{total_vulns}</div>
                <div class="stat-label">Vulnerabilities Found</div>
            </div>
        </div>

        <h2>Projects Overview</h2>
        <table>
            <tr>
                <th>Project</th>
                <th>Dependencies</th>
                <th>Vulnerabilities</th>
                <th>Last Updated</th>
            </tr>
"""

        for project_name, data in sorted(self.current_registry.items()):
            vuln_count = len(data.get("vulnerabilities", []))
            vuln_cell = f"<span class='badge critical'>{vuln_count} found</span>" if vuln_count > 0 else "<span class='badge clean'>None</span>"
            html += f"""            <tr>
                <td><strong>{project_name}</strong></td>
                <td>{data.get('package_count', 0)}</td>
                <td>{vuln_cell}</td>
                <td><span class='timestamp'>{data.get('timestamp', 'N/A')}</span></td>
            </tr>
"""

        html += "        </table>\n"

        has_changes = any([
            changes["new_projects"],
            changes["removed_projects"],
            changes["new_vulnerabilities"],
            changes["added_packages"],
            changes["removed_packages"],
        ])

        if has_changes:
            html += "        <h2>Changes Detected</h2>\n"

            if changes["new_projects"]:
                badges = " ".join(f"<span class='badge new'>{p}</span>" for p in changes["new_projects"])
                html += f"        <div class='alert'><strong>New Projects ({len(changes['new_projects'])}):</strong> {badges}</div>\n"

            if changes["removed_projects"]:
                badges = " ".join(f"<span class='badge removed'>{p}</span>" for p in changes["removed_projects"])
                html += f"        <div class='alert'><strong>Removed Projects ({len(changes['removed_projects'])}):</strong> {badges}</div>\n"

            if changes["new_vulnerabilities"]:
                html += "        <div class='alert danger'><strong>New Vulnerabilities Detected:</strong>\n"
                for project, vulns in sorted(changes["new_vulnerabilities"].items()):
                    html += f"            <p><strong>{project}:</strong></p>\n"
                    for vuln in sorted(vulns, key=self._vuln_sort_key):
                        vid = vuln.get("id", vuln.get("vulnerability_id", "N/A"))
                        badge_cls = "cve" if vid.startswith("CVE-") else "ghsa"
                        html += f"""            <div class="vulnerability">
                <strong>{vuln.get('name', 'Unknown')}</strong> v{vuln.get('version', vuln.get('installed_version', 'N/A'))}
                <span class="badge {badge_cls}">{vid}</span>
            </div>
"""
                html += "        </div>\n"

            # Dependency diff section
            all_added = changes.get("added_packages", {})
            all_removed = changes.get("removed_packages", {})
            if all_added or all_removed:
                html += "        <h2>Dependency Changes</h2>\n"
                for project_name in sorted(set(list(all_added) + list(all_removed))):
                    html += f"        <h3>{project_name}</h3>\n"
                    added = all_added.get(project_name, {})
                    removed = all_removed.get(project_name, {})
                    if added:
                        pkgs = " ".join(
                            f"<span class='pkg-diff pkg-added'>+ {k} {v}</span>"
                            for k, v in sorted(added.items())
                        )
                        html += f"        <p><strong>Added:</strong> {pkgs}</p>\n"
                    if removed:
                        pkgs = " ".join(
                            f"<span class='pkg-diff pkg-removed'>- {k} {v}</span>"
                            for k, v in sorted(removed.items())
                        )
                        html += f"        <p><strong>Removed:</strong> {pkgs}</p>\n"

        # Full vulnerability listing
        if self.all_vulnerabilities:
            html += "        <h2>All Vulnerabilities</h2>\n"
            for project_name, vulns in sorted(self.all_vulnerabilities.items()):
                if vulns:
                    html += f"        <h3>{project_name}</h3>\n"
                    for vuln in sorted(vulns, key=self._vuln_sort_key):
                        vid = vuln.get("id", vuln.get("vulnerability_id", "N/A"))
                        badge_cls = "cve" if vid.startswith("CVE-") else "ghsa"
                        fixed = vuln.get("fix_versions", vuln.get("fixed_versions", []))
                        fixed_str = fixed[0] if isinstance(fixed, list) and fixed else (fixed or "N/A")
                        html += f"""        <div class="vulnerability">
            <strong>{vuln.get('name', 'Unknown')}</strong>
            <span class="badge {badge_cls}">{vid}</span><br>
            <strong>Installed:</strong> {vuln.get('version', vuln.get('installed_version', 'N/A'))}<br>
            <strong>Fixed in:</strong> {fixed_str}
        </div>
"""

        html += """        <div class="footer">
            <p>Run this script regularly with a cron job to track changes over time.</p>
            <p>Full data available in JSON format at the output directory.</p>
        </div>
    </div>
</body>
</html>
"""

        with open(self.report_file, "w") as f:
            f.write(html)
        self.logger.info("HTML report generated: %s", self.report_file)

    def _send_notifications(self, config_path: Path, changes: Dict):
        """Send notifications via configured channels if there are alerts."""
        config_path = config_path.expanduser()
        if not config_path.exists():
            self.logger.debug("Notifications config not found at %s, skipping", config_path)
            return

        has_alerts = any([
            changes.get("new_vulnerabilities"),
            changes.get("new_projects"),
            changes.get("removed_projects"),
        ])

        if not has_alerts:
            self.logger.debug("No alerts to send notifications for")
            return

        try:
            from sbom_notifications import NotificationManager

            manager = NotificationManager(config_path)

            if manager.config.get("email", {}).get("enabled"):
                plain, html = NotificationManager.create_email_body(changes, self.current_registry)
                manager.send_email(
                    subject="SBOM Alert: Vulnerabilities Detected",
                    body=plain,
                    html_body=html,
                    to_addresses=manager.config["email"].get("recipients", [])
                )

            if manager.config.get("slack", {}).get("enabled"):
                message = NotificationManager.create_slack_message(changes, self.current_registry)
                manager.send_slack(message)

            if manager.config.get("webhook", {}).get("enabled"):
                webhook_url = manager.config["webhook"].get("url", "")
                if webhook_url:
                    payload = {
                        "timestamp": datetime.now().isoformat(),
                        "new_vulnerabilities": changes.get("new_vulnerabilities", {}),
                        "new_projects": changes.get("new_projects", []),
                        "removed_projects": changes.get("removed_projects", []),
                    }
                    manager.send_webhook(webhook_url, payload)

            if manager.config.get("macos", {}).get("enabled"):
                new_vulns = changes.get("new_vulnerabilities", {})
                vuln_count = sum(len(v) for v in new_vulns.values())
                affected = ", ".join(sorted(new_vulns.keys()))
                manager.send_macos_notification(
                    title="SBOM Monitor Alert",
                    message=f"{vuln_count} new vulnerability/vulnerabilities detected",
                    subtitle=affected,
                )

        except ImportError:
            self.logger.error("Could not import sbom_notifications -- notifications not sent")
        except Exception as e:
            self.logger.error("Failed to send notifications: %s", e)

    def run(self, notifications_config: Optional[Path] = None, max_workers: int = 4) -> int:
        """Run the full SBOM monitoring pipeline."""
        self.logger.info("Discovering projects in %s", self.projects_root)
        projects = self.discover_projects()

        if not projects:
            self.logger.warning("No projects found with venv directories")
            return 1

        self.logger.info("Found %d projects", len(projects))

        success_count = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, len(projects))) as executor:
            futures = {executor.submit(self.process_project, p): p for p in projects}
            for future in concurrent.futures.as_completed(futures):
                project = futures[future]
                try:
                    if future.result():
                        success_count += 1
                except Exception as e:
                    self.logger.error("Unexpected error processing %s: %s", project.name, e)

        self.logger.info("Successfully processed %d/%d projects", success_count, len(projects))

        changes = self.detect_changes()

        if any([changes["new_projects"], changes["removed_projects"], changes["new_vulnerabilities"]]):
            self.logger.warning("Changes detected:")
            if changes["new_projects"]:
                self.logger.warning("  %d new project(s)", len(changes["new_projects"]))
            if changes["removed_projects"]:
                self.logger.warning("  %d removed project(s)", len(changes["removed_projects"]))
            if changes["new_vulnerabilities"]:
                total_new = sum(len(v) for v in changes["new_vulnerabilities"].values())
                self.logger.warning("  %d new vulnerability/vulnerabilities", total_new)
        else:
            self.logger.info("No changes detected since last run")

        self.save_registry()
        self.save_vulnerabilities()
        self.generate_html_report(changes)

        if notifications_config:
            self._send_notifications(notifications_config, changes)

        self.logger.info("SBOM monitoring complete!")

        if success_count == 0:
            return 2
        if success_count < len(projects):
            return 1
        return 0


def main():
    parser = argparse.ArgumentParser(
        description="Monitor Python project dependencies and vulnerabilities"
    )
    parser.add_argument(
        "--projects",
        type=Path,
        default=Path("~/projects"),
        help="Root directory containing projects (default: ~/projects)"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("~/.sbom-monitor"),
        help="Directory to store SBOM registry and reports (default: ~/.sbom-monitor)"
    )
    parser.add_argument(
        "--notifications-config",
        type=Path,
        default=None,
        help="Path to notifications.json config file (optional)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout in seconds for subprocess calls (default: 30)"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Maximum parallel workers for project scanning (default: 4)"
    )

    args = parser.parse_args()

    monitor = SBOMMonitor(args.projects, args.output, scan_timeout=args.timeout)
    return monitor.run(
        notifications_config=args.notifications_config,
        max_workers=args.workers,
    )


if __name__ == "__main__":
    sys.exit(main())
