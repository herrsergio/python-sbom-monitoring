#!/usr/bin/env python3
"""
SBOM Monitor Notifications
Send alerts via email, Slack, or other channels when vulnerabilities are detected.
"""

import json
import os
from pathlib import Path
from typing import Optional, List, Dict
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import subprocess
import argparse


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

    def send_email(
        self,
        subject: str,
        body: str,
        html_body: Optional[str] = None,
        to_addresses: Optional[List[str]] = None
    ) -> bool:
        """Send notification via email."""
        config = self.config.get("email", {})

        if not all([config.get("sender"), config.get("smtp_server"), to_addresses]):
            print("❌ Email configuration incomplete")
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

                if config.get("password"):
                    server.login(config["sender"], config["password"])

                server.send_message(msg)

            print(f"✓ Email sent to {', '.join(to_addresses)}")
            return True
        except Exception as e:
            print(f"❌ Failed to send email: {e}")
            return False

    def send_slack(self, message: str, webhook_url: Optional[str] = None) -> bool:
        """Send notification to Slack."""
        url = webhook_url or self.config.get("slack", {}).get("webhook_url")

        if not url:
            print("❌ Slack webhook URL not configured")
            return False

        try:
            import requests

            payload = {"text": message}
            response = requests.post(url, json=payload, timeout=10)

            if response.status_code == 200:
                print("✓ Slack notification sent")
                return True
            else:
                print(f"❌ Slack API error: {response.status_code}")
                return False
        except ImportError:
            print("❌ requests library not installed (pip install requests)")
            return False
        except Exception as e:
            print(f"❌ Failed to send Slack message: {e}")
            return False

    def send_webhook(self, webhook_url: str, payload: Dict) -> bool:
        """Send notification to a generic webhook."""
        try:
            import requests

            response = requests.post(webhook_url, json=payload, timeout=10)

            if response.status_code in [200, 201, 202]:
                print(f"✓ Webhook notification sent ({response.status_code})")
                return True
            else:
                print(f"❌ Webhook error: {response.status_code}")
                return False
        except ImportError:
            print("❌ requests library not installed (pip install requests)")
            return False
        except Exception as e:
            print(f"❌ Failed to send webhook: {e}")
            return False

    @staticmethod
    def create_email_body(changes: Dict, registry: Dict) -> tuple[str, str]:
        """Create email subject and HTML body for vulnerability alerts."""
        vuln_count = sum(len(v) for v in changes.get("new_vulnerabilities", {}).values())
        new_projects = len(changes.get("new_projects", []))
        removed_projects = len(changes.get("removed_projects", []))

        subject = f"🔐 SBOM Alert: {vuln_count} new vulnerability/vulnerabilities"
        if new_projects:
            subject += f", {new_projects} new project(s)"

        plain_body = f"SBOM Monitor Alert\n\n"

        html_body = """
<html>
<head>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
        .container { max-width: 600px; margin: 0 auto; }
        .header { background: #0066cc; color: white; padding: 20px; border-radius: 4px 4px 0 0; }
        .content { background: #f9f9f9; padding: 20px; border-radius: 0 0 4px 4px; }
        .alert { background: #fff3cd; border-left: 4px solid #ff9800; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .alert.danger { background: #ffe6e6; border-left-color: #ff0000; }
        .vuln-item { background: white; padding: 12px; margin: 10px 0; border-left: 3px solid #ff0000; border-radius: 2px; }
        .vuln-item strong { color: #333; }
        .footer { color: #999; font-size: 12px; margin-top: 20px; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f0f0f0; font-weight: 600; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>🔐 SBOM Monitor Alert</h2>
            <p>Timestamp: {timestamp}</p>
        </div>
        <div class="content">
""".format(timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        # Summary
        if vuln_count > 0:
            html_body += f"""
            <div class="alert danger">
                <strong>⚠️ {vuln_count} New Vulnerability/Vulnerabilities Detected!</strong>
            </div>
"""
            plain_body += f"⚠️ {vuln_count} new vulnerability/vulnerabilities found\n"

        if new_projects > 0:
            html_body += f"""
            <div class="alert">
                <strong>✨ {new_projects} New Project(s)</strong><br>
                {', '.join(changes['new_projects'])}
            </div>
"""
            plain_body += f"\n✨ {new_projects} new project(s):\n"
            plain_body += "\n".join(f"  • {p}" for p in changes["new_projects"]) + "\n"

        if removed_projects > 0:
            html_body += f"""
            <div class="alert">
                <strong>🗑️ {removed_projects} Project(s) Removed</strong><br>
                {', '.join(changes['removed_projects'])}
            </div>
"""
            plain_body += f"\n🗑️ {removed_projects} project(s) removed:\n"
            plain_body += "\n".join(f"  • {p}" for p in changes["removed_projects"]) + "\n"

        # Vulnerability details
        if changes.get("new_vulnerabilities"):
            html_body += """
            <h3>Vulnerability Details</h3>
            <table>
                <tr>
                    <th>Project</th>
                    <th>Package</th>
                    <th>Installed</th>
                    <th>Severity</th>
                </tr>
"""
            plain_body += "\n" + "=" * 60 + "\nVULNERABILITY DETAILS\n" + "=" * 60 + "\n"

            for project, vulns in sorted(changes["new_vulnerabilities"].items()):
                for vuln in vulns:
                    severity = vuln.get("vulnerability_id", "UNKNOWN")
                    installed = vuln.get("installed_version", "N/A")
                    package = vuln.get("name", "Unknown")

                    html_body += f"""
                <tr>
                    <td><strong>{project}</strong></td>
                    <td>{package}</td>
                    <td>{installed}</td>
                    <td><span style="color: red; font-weight: bold;">{severity}</span></td>
                </tr>
"""
                    plain_body += f"\n{project}\n  Package: {package}\n  Installed: {installed}\n  ID: {severity}\n"

        # Stats
        html_body += f"""
            <h3>Monitored Projects</h3>
            <p>Total projects: <strong>{len(registry)}</strong></p>
            <p>Total dependencies: <strong>{sum(p.get('package_count', 0) for p in registry.values())}</strong></p>
        </div>
        <div class="footer">
            <p>💡 Review the full report and take action on critical vulnerabilities.</p>
        </div>
    </div>
</body>
</html>
"""

        plain_body += f"\n\nMonitored Projects: {len(registry)}\n"
        plain_body += f"Total Dependencies: {sum(p.get('package_count', 0) for p in registry.values())}\n"

        return plain_body, html_body

    @staticmethod
    def create_slack_message(changes: Dict, registry: Dict) -> str:
        """Create a Slack message for vulnerability alerts."""
        vuln_count = sum(len(v) for v in changes.get("new_vulnerabilities", {}).values())

        message = "🔐 *SBOM Monitor Alert*\n\n"

        if vuln_count > 0:
            message += f"⚠️ *{vuln_count} New Vulnerability/Vulnerabilities Detected!*\n"

        if changes.get("new_projects"):
            message += f"✨ *New Projects*: {', '.join(changes['new_projects'])}\n"

        if changes.get("removed_projects"):
            message += f"🗑️ *Removed Projects*: {', '.join(changes['removed_projects'])}\n"

        message += f"\n📊 *Summary*\n"
        message += f"  • Monitored Projects: {len(registry)}\n"
        message += f"  • Total Dependencies: {sum(p.get('package_count', 0) for p in registry.values())}\n"

        if changes.get("new_vulnerabilities"):
            message += f"\n🚨 *Affected Projects*:\n"
            for project, vulns in sorted(changes["new_vulnerabilities"].items()):
                message += f"  • {project}: {len(vulns)} vulnerability/vulnerabilities\n"

        return message


def create_config_template(output_file: Path):
    """Create a configuration template file."""
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
        }
    }

    with open(output_file, "w") as f:
        json.dump(template, f, indent=2)

    print(f"✓ Configuration template created: {output_file}")
    print(f"  📝 Edit this file with your notification settings")


def main():
    parser = argparse.ArgumentParser(
        description="Send SBOM vulnerability notifications"
    )
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

    # Load data
    with open(args.registry) as f:
        registry = json.load(f)

    # Detect changes
    changes = {
        "new_vulnerabilities": {},
        "new_projects": [],
        "removed_projects": []
    }

    if args.previous_vulns and Path(args.previous_vulns).exists():
        with open(args.previous_vulns) as f:
            prev_vulns = json.load(f)

        for project, vulns in registry.items():
            project_vulns = vulns.get("vulnerabilities", [])
            prev_project_vulns = prev_vulns.get(project, [])

            new_vulns = [v for v in project_vulns if v not in prev_project_vulns]
            if new_vulns:
                changes["new_vulnerabilities"][project] = new_vulns

    if not changes["new_vulnerabilities"]:
        print("✓ No new vulnerabilities detected")
        return 0

    print(f"⚠️ Detected {sum(len(v) for v in changes['new_vulnerabilities'].values())} new vulnerability/vulnerabilities")

    # Send notifications
    manager = NotificationManager(args.config)

    if manager.config.get("email", {}).get("enabled"):
        plain, html = NotificationManager.create_email_body(
            changes,
            registry
        )
        manager.send_email(
            subject=f"🔐 SBOM Alert: Vulnerabilities Detected",
            body=plain,
            html_body=html,
            to_addresses=manager.config["email"].get("recipients", [])
        )

    if manager.config.get("slack", {}).get("enabled"):
        message = NotificationManager.create_slack_message(changes, registry)
        manager.send_slack(message)

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())

