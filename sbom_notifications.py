#!/usr/bin/env python3
"""
SBOM Monitor Notifications
Send alerts via email, Slack, or other channels when vulnerabilities are detected.

Can be used standalone (CLI) or imported by sbom_monitor.py for automatic alerting.
"""

import json
import logging
import os
import stat
import subprocess
import sys
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Optional, List, Dict
from datetime import datetime


logger = logging.getLogger(__name__)


class NotificationManager:
    """Handle notifications for SBOM vulnerabilities."""

    def __init__(self, config_file: Path):
        self.config_file = config_file.expanduser()
        self.config = self._load_config()

    def _load_config(self) -> Dict:
        """Load notification configuration."""
        if self.config_file.exists():
            with open(self.config_file) as f:
                return json.load(f)
        return {}

    def _email_config_valid(self) -> bool:
        """Check that required email config fields are present and non-empty."""
        config = self.config.get("email", {})
        return bool(
            config.get("sender", "").strip()
            and config.get("smtp_server", "").strip()
            and config.get("password", "").strip()
        )

    def send_email(
        self,
        subject: str,
        body: str,
        html_body: Optional[str] = None,
        to_addresses: Optional[List[str]] = None
    ) -> bool:
        """Send notification via email."""
        config = self.config.get("email", {})

        if not self._email_config_valid():
            logger.error("Email configuration is incomplete or has empty required fields")
            return False

        if not to_addresses:
            logger.error("No recipients specified for email")
            return False

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = config["sender"]
            msg["To"] = ", ".join(to_addresses)

            msg.attach(MIMEText(body, "plain"))
            if html_body:
                msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(config["smtp_server"], config.get("smtp_port", 587)) as server:
                if config.get("use_tls"):
                    server.starttls()
                server.login(config["sender"], config["password"])
                server.send_message(msg)

            logger.info("Email sent to %s", ", ".join(to_addresses))
            return True
        except Exception as e:
            logger.error("Failed to send email: %s", e)
            return False

    def send_slack(self, message: str, webhook_url: Optional[str] = None) -> bool:
        """Send notification to Slack."""
        url = webhook_url or self.config.get("slack", {}).get("webhook_url", "")

        if not url.strip():
            logger.error("Slack webhook URL not configured")
            return False

        try:
            import requests

            response = requests.post(url, json={"text": message}, timeout=10)
            if response.status_code == 200:
                logger.info("Slack notification sent")
                return True
            logger.error("Slack API error: %s", response.status_code)
            return False
        except ImportError:
            logger.error("requests library not installed (pip install requests)")
            return False
        except Exception as e:
            logger.error("Failed to send Slack message: %s", e)
            return False

    def send_webhook(self, webhook_url: str, payload: Dict) -> bool:
        """Send notification to a generic webhook."""
        try:
            import requests

            response = requests.post(webhook_url, json=payload, timeout=10)
            if response.status_code in [200, 201, 202]:
                logger.info("Webhook notification sent (%s)", response.status_code)
                return True
            logger.error("Webhook error: %s", response.status_code)
            return False
        except ImportError:
            logger.error("requests library not installed (pip install requests)")
            return False
        except Exception as e:
            logger.error("Failed to send webhook: %s", e)
            return False

    def send_macos_notification(self, title: str, message: str, subtitle: str = "") -> bool:
        """Send a macOS notification via osascript (no external dependencies required)."""
        if sys.platform != "darwin":
            logger.debug("macOS notifications are only supported on macOS")
            return False

        config = self.config.get("macos", {})
        sound = config.get("sound", "Basso")

        script = f'display notification "{message}" with title "{title}"'
        if subtitle:
            script += f' subtitle "{subtitle}"'
        if sound:
            script += f' sound name "{sound}"'

        try:
            result = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                logger.info("macOS notification sent")
                return True
            logger.error("osascript error: %s", result.stderr.decode().strip())
            return False
        except Exception as e:
            logger.error("Failed to send macOS notification: %s", e)
            return False

    @staticmethod
    def create_email_body(changes: Dict, registry: Dict) -> tuple[str, str]:
        """Create plain text and HTML email body for vulnerability alerts."""
        vuln_count = sum(len(v) for v in changes.get("new_vulnerabilities", {}).values())
        new_projects = len(changes.get("new_projects", []))
        removed_projects = len(changes.get("removed_projects", []))

        plain_body = "SBOM Monitor Alert\n\n"

        html_body = """<html>
<head>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }}
        .container {{ max-width: 600px; margin: 0 auto; }}
        .header {{ background: #0066cc; color: white; padding: 20px; border-radius: 4px 4px 0 0; }}
        .content {{ background: #f9f9f9; padding: 20px; border-radius: 0 0 4px 4px; }}
        .alert {{ background: #fff3cd; border-left: 4px solid #ff9800; padding: 15px; margin: 10px 0; border-radius: 4px; }}
        .alert.danger {{ background: #ffe6e6; border-left-color: #ff0000; }}
        .footer {{ color: #999; font-size: 12px; margin-top: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f0f0f0; font-weight: 600; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>SBOM Monitor Alert</h2>
            <p>Timestamp: {timestamp}</p>
        </div>
        <div class="content">
""".format(timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        if vuln_count > 0:
            html_body += f'            <div class="alert danger"><strong>{vuln_count} New Vulnerability/Vulnerabilities Detected!</strong></div>\n'
            plain_body += f"{vuln_count} new vulnerability/vulnerabilities found\n"

        if new_projects > 0:
            html_body += f'            <div class="alert"><strong>{new_projects} New Project(s):</strong> {", ".join(changes["new_projects"])}</div>\n'
            plain_body += f"\n{new_projects} new project(s):\n" + "\n".join(f"  - {p}" for p in changes["new_projects"]) + "\n"

        if removed_projects > 0:
            html_body += f'            <div class="alert"><strong>{removed_projects} Project(s) Removed:</strong> {", ".join(changes["removed_projects"])}</div>\n'
            plain_body += f"\n{removed_projects} project(s) removed:\n" + "\n".join(f"  - {p}" for p in changes["removed_projects"]) + "\n"

        if changes.get("new_vulnerabilities"):
            html_body += """            <h3>Vulnerability Details</h3>
            <table>
                <tr><th>Project</th><th>Package</th><th>Installed</th><th>ID</th></tr>
"""
            plain_body += "\n" + "=" * 60 + "\nVULNERABILITY DETAILS\n" + "=" * 60 + "\n"
            for project, vulns in sorted(changes["new_vulnerabilities"].items()):
                for vuln in vulns:
                    vid = vuln.get("id", vuln.get("vulnerability_id", "UNKNOWN"))
                    installed = vuln.get("version", vuln.get("installed_version", "N/A"))
                    package = vuln.get("name", "Unknown")
                    html_body += f'                <tr><td><strong>{project}</strong></td><td>{package}</td><td>{installed}</td><td style="color:red;font-weight:bold">{vid}</td></tr>\n'
                    plain_body += f"\n{project}\n  Package: {package}\n  Installed: {installed}\n  ID: {vid}\n"
            html_body += "            </table>\n"

        total_deps = sum(p.get("package_count", 0) for p in registry.values())
        html_body += f"""        </div>
        <div class="footer">
            <p>Monitored Projects: <strong>{len(registry)}</strong> | Total Dependencies: <strong>{total_deps}</strong></p>
        </div>
    </div>
</body>
</html>
"""
        plain_body += f"\nMonitored Projects: {len(registry)}\nTotal Dependencies: {total_deps}\n"

        return plain_body, html_body

    @staticmethod
    def create_slack_message(changes: Dict, registry: Dict) -> str:
        """Create a Slack message for vulnerability alerts."""
        vuln_count = sum(len(v) for v in changes.get("new_vulnerabilities", {}).values())

        message = "*SBOM Monitor Alert*\n\n"

        if vuln_count > 0:
            message += f"*{vuln_count} New Vulnerability/Vulnerabilities Detected!*\n"

        if changes.get("new_projects"):
            message += f"*New Projects*: {', '.join(changes['new_projects'])}\n"

        if changes.get("removed_projects"):
            message += f"*Removed Projects*: {', '.join(changes['removed_projects'])}\n"

        message += "\n*Summary*\n"
        message += f"  - Monitored Projects: {len(registry)}\n"
        message += f"  - Total Dependencies: {sum(p.get('package_count', 0) for p in registry.values())}\n"

        if changes.get("new_vulnerabilities"):
            message += "\n*Affected Projects*:\n"
            for project, vulns in sorted(changes["new_vulnerabilities"].items()):
                message += f"  - {project}: {len(vulns)} vulnerability/vulnerabilities\n"

        return message


def create_config_template(output_file: Path):
    """Create a configuration template file with secure permissions (0600)."""
    template = {
        "email": {
            "enabled": False,
            "sender": "your-email@example.com",
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "use_tls": True,
            "password": "your-app-password",
            "recipients": ["admin@example.com"]
        },
        "slack": {
            "enabled": False,
            "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
        },
        "webhook": {
            "enabled": False,
            "url": "https://your-webhook-endpoint.com/sbom-alerts",
            "secret": "optional-secret-key"
        },
        "macos": {
            "enabled": False,
            "sound": "Basso"
        }
    }

    output_file = output_file.expanduser()
    with open(output_file, "w") as f:
        json.dump(template, f, indent=2)

    # Restrict to owner read/write only since the file contains credentials
    os.chmod(output_file, stat.S_IRUSR | stat.S_IWUSR)

    print(f"Configuration template created: {output_file}")
    print("  File permissions set to 600 (owner read/write only)")
    print("  Edit this file with your notification settings, then set 'enabled': true")


def main():
    import sys
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    parser = argparse.ArgumentParser(description="Send SBOM vulnerability notifications")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("~/.sbom-monitor/notifications.json"),
        help="Notification configuration file"
    )
    parser.add_argument(
        "--registry",
        type=Path,
        required=True,
        help="SBOM registry file"
    )
    parser.add_argument(
        "--previous-vulns",
        type=Path,
        help="Previous vulnerabilities file for change detection"
    )
    parser.add_argument(
        "--create-template",
        action="store_true",
        help="Create a notification configuration template"
    )

    args = parser.parse_args()

    if args.create_template:
        create_config_template(args.config)
        return 0

    with open(args.registry) as f:
        registry = json.load(f)

    changes: Dict = {
        "new_vulnerabilities": {},
        "new_projects": [],
        "removed_projects": []
    }

    if args.previous_vulns and Path(args.previous_vulns).exists():
        with open(args.previous_vulns) as f:
            prev_vulns = json.load(f)

        for project, data in registry.items():
            project_vulns = data.get("vulnerabilities", [])
            prev_project_vulns = prev_vulns.get(project, [])
            # Compare by (name, id) tuple to be robust against dict key ordering
            prev_ids = {
                (v.get("name", ""), v.get("id", v.get("vulnerability_id", "")))
                for v in prev_project_vulns
            }
            new_vulns = [
                v for v in project_vulns
                if (v.get("name", ""), v.get("id", v.get("vulnerability_id", ""))) not in prev_ids
            ]
            if new_vulns:
                changes["new_vulnerabilities"][project] = new_vulns

    if not changes["new_vulnerabilities"]:
        logger.info("No new vulnerabilities detected")
        return 0

    total = sum(len(v) for v in changes["new_vulnerabilities"].values())
    logger.warning("Detected %d new vulnerability/vulnerabilities", total)

    manager = NotificationManager(args.config)

    if manager.config.get("email", {}).get("enabled"):
        plain, html = NotificationManager.create_email_body(changes, registry)
        manager.send_email(
            subject="SBOM Alert: Vulnerabilities Detected",
            body=plain,
            html_body=html,
            to_addresses=manager.config["email"].get("recipients", [])
        )

    if manager.config.get("slack", {}).get("enabled"):
        message = NotificationManager.create_slack_message(changes, registry)
        manager.send_slack(message)

    if manager.config.get("webhook", {}).get("enabled"):
        webhook_url = manager.config["webhook"].get("url", "")
        if webhook_url:
            payload = {
                "timestamp": datetime.now().isoformat(),
                "new_vulnerabilities": changes["new_vulnerabilities"],
                "new_projects": changes["new_projects"],
                "removed_projects": changes["removed_projects"],
            }
            manager.send_webhook(webhook_url, payload)

    if manager.config.get("macos", {}).get("enabled"):
        vuln_count = sum(len(v) for v in changes["new_vulnerabilities"].values())
        affected = ", ".join(sorted(changes["new_vulnerabilities"].keys()))
        manager.send_macos_notification(
            title="SBOM Monitor Alert",
            message=f"{vuln_count} new vulnerability/vulnerabilities detected",
            subtitle=affected,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
