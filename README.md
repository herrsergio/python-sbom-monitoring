# 🔐 SBOM Monitor - Python Dependency & Vulnerability Tracker

A comprehensive tool for monitoring Python projects, generating Software Bill of Materials (SBOMs), tracking vulnerabilities, and receiving alerts about supply chain risks.

## Features

✅ **Auto-Discovery**: Finds all projects with `.venv` or `venv` directories

✅ **SBOM Generation**: Creates CycloneDX SBOMs for each project

✅ **Vulnerability Scanning**: Uses `pip-audit` to detect known CVEs

✅ **Change Tracking**: Detects new projects, removed projects, and new vulnerabilities

✅ **Historical Registry**: Maintains JSON registry of all dependencies over time

✅ **HTML Reports**: Beautiful visual reports of security status

✅ **Automated Scheduling**: Cron integration for daily/weekly scans

✅ **Multi-Channel Alerts**: Email, Slack, and custom webhooks

✅ **Lightweight**: Minimal dependencies, works with existing venvs


## Quick Start

### 1. Installation

```bash
# Download the scripts
git clone <repo> sbom-monitor
cd sbom-monitor

# Or manually download:
# - sbom
# - setup-sbom-monitor.sh
# - sbom_notifications.py

# Make setup script executable
chmod +x setup-sbom-monitor.sh

# Run setup wizard
./setup-sbom-monitor.sh
```

### 2. First Run

The setup wizard will:
- Ask for your projects directory (default: `~/projects`)
- Ask for output directory (default: `~/.sbom-monitor`)
- Optionally set up automated cron jobs
- Run an initial scan

### 3. View Results

```bash
# Open HTML report
open ~/.sbom-monitor/report.html

# Check JSON registry
cat ~/.sbom-monitor/sbom-registry.json

# View vulnerabilities
cat ~/.sbom-monitor/vulnerabilities.json
```

## Usage

### Manual Scans

```bash
# Activate the monitor's venv
source ./venv-monitor/bin/activate

# Run a full scan
python sbom \
  --projects ~/projects \
  --output ~/.sbom-monitor

# Custom locations
python sbom \
  --projects /path/to/projects \
  --output /path/to/output
```

### Scheduled Scans

The setup wizard creates a cron job. To manually configure:

```bash
# Edit crontab
crontab -e

# Add entry for daily 2 AM scans:
0 2 * * * /path/to/run-sbom-monitor.sh

# Or weekly Sundays at 3 AM:
0 3 * * 0 /path/to/run-sbom-monitor.sh
```

### Generate Notifications

```bash
# Create notification config template
source ./venv-monitor/bin/activate
python sbom_notifications.py \
  --registry ~/.sbom-monitor/sbom-registry.json \
  --create-template

# Edit the config
nano ~/.sbom-monitor/notifications.json

# Send notifications (run after sbom)
python sbom_notifications.py \
  --config ~/.sbom-monitor/notifications.json \
  --registry ~/.sbom-monitor/sbom-registry.json
```

## Configuration

### Notification Setup

The notification configuration file (`~/.sbom-monitor/notifications.json`) supports:

#### Email Notifications

```json
{
  "email": {
    "enabled": true,
    "sender": "sbom-alerts@example.com",
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "use_tls": true,
    "password": "your-app-specific-password",
    "recipients": ["ops@example.com", "security@example.com"]
  }
}
```

**Gmail Setup:**
1. Enable 2-factor authentication
2. Create an [App Password](https://myaccount.google.com/apppasswords)
3. Use the app password in the config (not your regular password)

#### Slack Notifications

```json
{
  "slack": {
    "enabled": true,
    "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
  }
}
```

**Slack Setup:**
1. Go to your Slack workspace settings
2. Create a new Incoming Webhook: https://api.slack.com/messaging/webhooks
3. Copy the webhook URL to config

#### Custom Webhook

```json
{
  "webhook": {
    "enabled": true,
    "url": "https://your-system.com/webhooks/sbom",
    "secret": "optional-secret-key"
  }
}
```

### Project Directory Structure

The tool expects projects like:

```
~/projects/
├── project-a/
│   ├── .venv/          # or venv/
│   ├── src/
│   ├── requirements.txt
│   └── pyproject.toml
├── project-b/
│   ├── .venv/
│   ├── app.py
│   └── requirements.txt
└── project-c/
    ├── venv/
    └── ...
```

## Output Files

After running `sbom`:

```
~/.sbom-monitor/
├── sbom-registry.json       # Complete registry of all projects/packages
├── vulnerabilities.json     # All detected vulnerabilities
├── report.html             # Beautiful HTML dashboard
└── monitor.log             # Log from automated runs (if cron enabled)
```

### Registry Format

```json
{
  "project-name": {
    "path": "/path/to/project",
    "timestamp": "2024-01-15T02:00:00",
    "package_count": 42,
    "sbom": { /* CycloneDX SBOM */ },
    "vulnerabilities": [
      {
        "name": "requests",
        "installed_version": "2.27.1",
        "vulnerability_id": "GHSA-xxx",
        "fixed_versions": ["2.28.0"]
      }
    ]
  }
}
```

## Interpreting Results

### HTML Report

The report includes:

- **Summary Stats**: Total projects, dependencies, vulnerabilities at a glance
- **Projects Table**: Status of each project and dependency count
- **Changes Section**: What's new/updated since last run
- **Vulnerability Details**: Each CVE with package info and fix recommendations

### Vulnerability Severity

Vulnerabilities are reported with their CVE ID. To research a CVE:

```bash
# Check NVD database
open "https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXXX"

# Or PyPI security page
open "https://pypi.org/project/{package}/#{cve-version}"
```

## Common Issues

### "Could not find Python executable in venv"

**Problem**: A project's venv wasn't detected properly

**Solution**:
```bash
# Recreate venv
cd ~/projects/your-project
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### "cyclonedx-bom not found" / "pip-audit not found"

**Solution**: The script falls back to `pip list` for SBOM generation, but install tools in monitor's venv:

```bash
source ./venv-monitor/bin/activate
pip install cyclonedx-bom pip-audit
```

### Cron job not running

**Check**:
```bash
# View cron log
log stream --predicate 'process == "cron"' --level debug

# Verify entry exists
crontab -l | grep sbom-monitor

# Test wrapper script manually
bash /path/to/run-sbom-monitor.sh
```

**Common causes**:
- Paths not absolute (use full paths in cron)
- Virtual environment not activated (wrapper script handles this)
- PATH not set (use full paths to python)

### Too many vulnerabilities reported

**Tip**: Check if these are transitive (indirect) dependencies:

```bash
cd ~/projects/your-project
source .venv/bin/activate

# See dependency tree
pip install pipdeptree
pipdeptree -p {package}

# Or upgrade everything
pip install --upgrade -r requirements.txt
```

## Best Practices

### 1. Baseline First Run
```bash
# Before making changes, establish a baseline
python sbom --projects ~/projects --output ~/.sbom-monitor
```

### 2. Schedule Regular Scans
```bash
# Daily at 2 AM
0 2 * * * /path/to/run-sbom-monitor.sh
```

### 3. Review Reports Weekly
- Check for new vulnerabilities in the HTML report
- Update packages with patches
- Track which projects have the most risk

### 4. Act on Critical CVEs
```bash
# For critical vulnerabilities:
cd ~/projects/affected-project
source .venv/bin/activate

# Check current version
pip show {package}

# Update to fixed version
pip install --upgrade {package}>=X.Y.Z

# Re-scan
python sbom --projects ~/projects --output ~/.sbom-monitor
```

### 5. Keep Audit Trail
The registry maintains history in JSON. Consider:
- Committing to git: `git add sbom-registry.json`
- Archiving old reports: `cp report.html report-2024-01-15.html`
- Comparing over time: `diff sbom-registry.json sbom-registry.old.json`

## Advanced Usage

### Integration with CI/CD

```yaml
# Example: GitHub Actions
name: SBOM Scan
on:
  schedule:
    - cron: '0 2 * * *'
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: |
          pip install pip-audit cyclonedx-bom
          python sbom --projects . --output ./sbom-reports
      - uses: actions/upload-artifact@v3
        with:
          name: sbom-reports
          path: sbom-reports/
```

### Export to External Systems

```bash
# Convert SBOM to CycloneDX standard format (for risk management tools)
python sbom --projects ~/projects --output ~/.sbom-monitor

# The sbom-registry.json can be imported into:
# - Dependency-Track (open-source SBOM management)
# - Black Duck / Synopsys
# - Snyk
# - JFrog XRay
```

### Custom Analysis Scripts

```python
import json

with open('~/.sbom-monitor/sbom-registry.json') as f:
    registry = json.load(f)

# Find all projects with outdated dependencies
for project, data in registry.items():
    vulns = data.get('vulnerabilities', [])
    if vulns:
        print(f"{project}: {len(vulns)} issues")
```

## Troubleshooting

### Debug Mode

For more verbose output, modify the script temporarily:

```python
# In sbom, add:
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Test Individual Projects

```bash
source ./venv-monitor/bin/activate

cd ~/projects/project-a
python -m pip_audit --desc --format json
```

### Check System Configuration

```bash
# Verify Python versions in venvs
for venv in ~/projects/*/.venv; do
  echo "$venv: $($venv/bin/python --version)"
done

# Check disk space
du -sh ~/.sbom-monitor/

# Monitor resources during scan
time python sbom ...
```

## Performance Notes

- First run: 1-5 minutes depending on number of projects
- Subsequent runs: 30 seconds - 2 minutes (faster due to caching)
- Disk usage: ~10MB per 100 projects with full SBOMs
- Memory: Minimal (<100MB)

For large numbers of projects (>50), consider:
- Splitting into separate monitor instances
- Running at off-peak hours
- Increasing cron timeout limits

## Support & Contributing

If you encounter issues:

1. Check the troubleshooting section above
2. Review error messages in monitor.log
3. Test the command manually with verbose output
4. Check that all dependencies are installed

## License & Security

⚠️ **Important Security Notes**:

- Never commit notification configs with credentials to git
- Use git secrets/pre-commit hooks to prevent accidental commits
- Rotate email app passwords and Slack tokens regularly
- Review the registry regularly for unusual package additions
- Keep the monitor script itself updated for security improvements

## Related Tools

- **pip-audit**: Direct vulnerability scanning (used internally)
- **Safety.io**: Additional vulnerability database
- **Dependabot**: GitHub-integrated dependency tracking
- **Snyk**: Commercial-grade SCA (software composition analysis)
- **Dependency-Track**: Open-source SBOM management platform
- **pyenv**: Python version management (works great with this tool!)

## FAQ

**Q: Can this monitor pip, poetry, and pipenv projects?**
A: Yes! As long as they have an activated venv with `pyvenv.cfg`, they'll be detected.

**Q: Does this work on macOS, Linux, and Windows?**
A: Yes. Windows users may need to adjust paths (uses both `/` and `\` in code).

**Q: How far back does the registry history go?**
A: Only the latest snapshot is kept. To track history, commit to git or archive reports.

**Q: Can I exclude certain projects?**
A: Edit the script to add a blacklist, or move projects outside the monitored directory.

**Q: What if a project has no venv yet?**
A: The tool skips it. You can run it on that project later after creating the venv.

---

**Questions or improvements?** Feel free to extend these scripts for your workflow!

