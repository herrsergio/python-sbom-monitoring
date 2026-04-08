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
"""

import json
import subprocess
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import hashlib
import argparse


class SBOMMonitor:
    def __init__(self, projects_root: Path, output_dir: Path):
        self.projects_root = projects_root.expanduser()
        self.output_dir = output_dir.expanduser()
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.registry_file = self.output_dir / "sbom-registry.json"
        self.vulns_file = self.output_dir / "vulnerabilities.json"
        self.report_file = self.output_dir / "report.html"

        self.previous_registry = self._load_registry()
        self.current_registry = {}
        self.all_vulnerabilities = {}

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
            print(f"⚠️  Projects root {self.projects_root} does not exist")
            return projects

        for item in self.projects_root.iterdir():
            if not item.is_dir():
                continue

            # Check for .venv or venv
            venv_dir = item / ".venv"
            if not venv_dir.exists():
                venv_dir = item / "venv"

            if venv_dir.exists() and (venv_dir / "pyvenv.cfg").exists():
                projects.append(item)
                print(f"✓ Found project: {item.name}")

        return sorted(projects)

    def get_python_executable(self, project: Path) -> Optional[Path]:
        """Find the Python executable in a project's venv."""
        for venv_name in [".venv", "venv"]:
            venv_path = project / venv_name
            if venv_path.exists():
                # Try Unix first, then Windows
                python = venv_path / "bin" / "python"
                if not python.exists():
                    python = venv_path / "Scripts" / "python.exe"
                if python.exists():
                    return python
        return None

    def get_installed_packages(self, python_exe: Path) -> Dict[str, str]:
        """Get installed packages and versions using pip list."""
        try:
            result = subprocess.run(
                [str(python_exe), "-m", "pip", "list", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                packages = json.loads(result.stdout)
                return {pkg["name"]: pkg["version"] for pkg in packages}
        except Exception as e:
            print(f"  ❌ Error getting packages: {e}")
        return {}

    def generate_sbom(self, project: Path, python_exe: Path) -> Optional[Dict]:
        """Generate SBOM using cyclonedx-bom."""
        try:
            # Check if cyclonedx-bom is available in venv
            result = subprocess.run(
                [str(python_exe), "-m", "pip", "show", "cyclonedx-bom"],
                capture_output=True,
                timeout=10
            )

            if result.returncode != 0:
                # Fall back to getting packages directly
                packages = self.get_installed_packages(python_exe)
                return {
                    "project": project.name,
                    "timestamp": datetime.now().isoformat(),
                    "packages": packages,
                    "method": "pip-list"
                }

            # Try using cyclonedx-py
            result = subprocess.run(
                [str(python_exe), "-m", "cyclonedx", "pip", "-o", "json"],
                capture_output=True,
                text=True,
                cwd=str(project),
                timeout=30
            )

            if result.returncode == 0:
                sbom = json.loads(result.stdout)
                return sbom
            else:
                # Fall back to pip list
                packages = self.get_installed_packages(python_exe)
                return {
                    "project": project.name,
                    "timestamp": datetime.now().isoformat(),
                    "packages": packages,
                    "method": "pip-list"
                }
        except subprocess.TimeoutExpired:
            print(f"  ⏱️  Timeout generating SBOM")
        except Exception as e:
            print(f"  ❌ Error generating SBOM: {e}")

        return None

    def scan_vulnerabilities(self, python_exe: Path, project: Path) -> List[Dict]:
        """Run pip-audit to find vulnerabilities."""
        try:
            result = subprocess.run(
                [str(python_exe), "-m", "pip", "install", "--quiet", "pip-audit"],
                timeout=30,
                capture_output=True
            )

            result = subprocess.run(
                [str(python_exe), "-m", "pip_audit", "--desc", "--format", "json"],
                capture_output=True,
                text=True,
                cwd=str(project),
                timeout=30
            )

            if result.returncode in [0, 1]:  # 0 = no vulns, 1 = vulns found
                try:
                    data = json.loads(result.stdout)
                    return data.get("vulnerabilities", [])
                except json.JSONDecodeError:
                    return []
        except subprocess.TimeoutExpired:
            print(f"  ⏱️  Timeout scanning vulnerabilities")
        except Exception as e:
            print(f"  ❌ Error scanning vulnerabilities: {e}")

        return []

    def process_project(self, project: Path) -> bool:
        """Process a single project: generate SBOM and scan for vulnerabilities."""
        print(f"\n📦 Processing: {project.name}")

        python_exe = self.get_python_executable(project)
        if not python_exe:
            print(f"  ❌ Could not find Python executable in venv")
            return False

        # Generate SBOM
        print(f"  📋 Generating SBOM...")
        sbom = self.generate_sbom(project, python_exe)
        if not sbom:
            print(f"  ❌ Failed to generate SBOM")
            return False

        # Scan for vulnerabilities
        print(f"  🔍 Scanning for vulnerabilities...")
        vulns = self.scan_vulnerabilities(python_exe, project)
        if vulns:
            print(f"  ⚠️  Found {len(vulns)} vulnerabilities")
            self.all_vulnerabilities[project.name] = vulns
        else:
            print(f"  ✓ No vulnerabilities found")

        # Store in registry
        packages = sbom.get("packages", sbom) if isinstance(sbom.get("packages"), dict) else {}
        self.current_registry[project.name] = {
            "path": str(project),
            "timestamp": datetime.now().isoformat(),
            "sbom": sbom,
            "vulnerabilities": vulns,
            "package_count": len(packages)
        }

        return True

    def detect_changes(self) -> Dict:
        """Detect what's changed since last run."""
        changes = {
            "new_projects": [],
            "removed_projects": [],
            "updated_dependencies": {},
            "new_vulnerabilities": {}
        }

        # New projects
        for project_name in self.current_registry:
            if project_name not in self.previous_registry:
                changes["new_projects"].append(project_name)

        # Removed projects
        for project_name in self.previous_registry:
            if project_name not in self.current_registry:
                changes["removed_projects"].append(project_name)

        # Check for new vulnerabilities
        for project_name, vulns in self.all_vulnerabilities.items():
            prev_vulns = self.previous_registry.get(project_name, {}).get("vulnerabilities", [])

            new_vulns = [v for v in vulns if v not in prev_vulns]
            if new_vulns:
                changes["new_vulnerabilities"][project_name] = new_vulns

        return changes

    def save_registry(self):
        """Save the current registry to disk."""
        with open(self.registry_file, "w") as f:
            json.dump(self.current_registry, f, indent=2)
        print(f"\n💾 Registry saved to {self.registry_file}")

    def save_vulnerabilities(self):
        """Save vulnerability report."""
        with open(self.vulns_file, "w") as f:
            json.dump(self.all_vulnerabilities, f, indent=2)
        print(f"💾 Vulnerabilities saved to {self.vulns_file}")

    def generate_html_report(self, changes: Dict):
        """Generate an HTML report."""
        html_content = f"""
<!DOCTYPE html>
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
        .stat-card.warning {{ background: #fff3cd; border-left-color: #ff9800; }}
        .stat-card.danger {{ background: #ffe6e6; border-left-color: #ff0000; }}
        .stat-number {{ font-size: 28px; font-weight: bold; color: #0066cc; }}
        .stat-card.warning .stat-number {{ color: #ff9800; }}
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
        .badge.updated {{ background: #cce5ff; color: #0066cc; }}
        .badge.removed {{ background: #e7d4d4; color: #721c24; }}
        .badge.critical {{ background: #ff0000; color: white; }}
        .vulnerability {{ background: #ffe6e6; border-left: 4px solid #ff0000; padding: 12px; margin: 10px 0; border-radius: 4px; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #999; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Python SBOM Monitor Report</h1>
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
            <div class="stat-card {'danger' if self.all_vulnerabilities else ''}">
                <div class="stat-number">{sum(len(v) for v in self.all_vulnerabilities.values())}</div>
                <div class="stat-label">Vulnerabilities Found</div>
            </div>
        </div>

        <h2>📊 Projects Overview</h2>
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
            vuln_badge = f"<span class='badge critical'>{vuln_count}</span>" if vuln_count > 0 else "✓"

            html_content += f"""
            <tr>
                <td><strong>{project_name}</strong></td>
                <td>{data.get('package_count', 0)}</td>
                <td>{vuln_badge}</td>
                <td><span class='timestamp'>{data.get('timestamp', 'N/A')}</span></td>
            </tr>
"""

        html_content += """
        </table>
"""

        # Changes section
        if any([changes["new_projects"], changes["removed_projects"], changes["updated_dependencies"], changes["new_vulnerabilities"]]):
            html_content += """
        <h2>🔄 Changes Detected</h2>
"""

            if changes["new_projects"]:
                html_content += f"""
        <div class="alert">
            <strong>✨ New Projects ({len(changes['new_projects'])}):</strong>
            {', '.join([f"<span class='badge new'>{p}</span>" for p in changes['new_projects']])}
        </div>
"""

            if changes["removed_projects"]:
                html_content += f"""
        <div class="alert">
            <strong>🗑️ Removed Projects ({len(changes['removed_projects'])}):</strong>
            {', '.join([f"<span class='badge removed'>{p}</span>" for p in changes['removed_projects']])}
        </div>
"""

            if changes["new_vulnerabilities"]:
                html_content += """
        <div class="alert danger">
            <strong>⚠️ New Vulnerabilities Detected:</strong>
"""
                for project, vulns in changes["new_vulnerabilities"].items():
                    html_content += f"<p><strong>{project}:</strong></p>"
                    for vuln in vulns:
                        html_content += f"""
            <div class="vulnerability">
                <strong>{vuln.get('name', 'Unknown')}</strong> v{vuln.get('installed_version', 'N/A')}<br>
                <small>CVE: {vuln.get('cve', 'N/A')} | Severity: {vuln.get('vulnerability_id', 'N/A')}</small>
            </div>
"""
                html_content += """
        </div>
"""

        # Vulnerabilities detail section
        if self.all_vulnerabilities:
            html_content += """
        <h2>🚨 All Vulnerabilities</h2>
"""
            for project_name, vulns in sorted(self.all_vulnerabilities.items()):
                if vulns:
                    html_content += f"<h3>{project_name}</h3>"
                    for vuln in vulns:
                        html_content += f"""
            <div class="vulnerability">
                <strong>{vuln.get('name', 'Unknown')}</strong><br>
                <strong>Installed:</strong> {vuln.get('installed_version', 'N/A')}<br>
                <strong>Fixed:</strong> {vuln.get('fixed_versions', ['N/A'])[0] if isinstance(vuln.get('fixed_versions'), list) else vuln.get('fixed_versions', 'N/A')}<br>
                <small>ID: {vuln.get('vulnerability_id', 'N/A')}</small>
            </div>
"""

        html_content += """
        <div class="footer">
            <p>💡 Tip: Run this script regularly with a cron job to track changes over time.</p>
            <p>📁 Full data available in JSON format at the output directory.</p>
        </div>
    </div>
</body>
</html>
"""

        with open(self.report_file, "w") as f:
            f.write(html_content)
        print(f"📊 HTML report generated: {self.report_file}")

    def run(self) -> int:
        """Run the full SBOM monitoring pipeline."""
        print(f"🔍 Discovering projects in {self.projects_root}...")
        projects = self.discover_projects()

        if not projects:
            print("⚠️  No projects found with venv directories")
            return 1

        print(f"\n✓ Found {len(projects)} projects\n")

        success_count = 0
        for project in projects:
            if self.process_project(project):
                success_count += 1

        print(f"\n{'='*60}")
        print(f"✓ Successfully processed {success_count}/{len(projects)} projects")

        # Detect changes
        changes = self.detect_changes()

        if any([changes["new_projects"], changes["removed_projects"], changes["new_vulnerabilities"]]):
            print(f"\n⚠️  Changes detected:")
            if changes["new_projects"]:
                print(f"   • {len(changes['new_projects'])} new project(s)")
            if changes["removed_projects"]:
                print(f"   • {len(changes['removed_projects'])} removed project(s)")
            if changes["new_vulnerabilities"]:
                total_new = sum(len(v) for v in changes["new_vulnerabilities"].values())
                print(f"   • {total_new} new vulnerability/vulnerabilities")
        else:
            print(f"\n✓ No changes detected since last run")

        # Save results
        self.save_registry()
        self.save_vulnerabilities()
        self.generate_html_report(changes)

        print(f"\n{'='*60}")
        print("✓ SBOM monitoring complete!")

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

    args = parser.parse_args()

    monitor = SBOMMonitor(args.projects, args.output)
    return monitor.run()


if __name__ == "__main__":
    sys.exit(main())

