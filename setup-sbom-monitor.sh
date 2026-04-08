#!/usr/bin/env bash
#
# SBOM Monitor Setup Script
# Installs dependencies, sets up configuration, and configures automated runs.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME="sbom_monitor.py"
SCRIPT_PATH="$SCRIPT_DIR/$SCRIPT_NAME"

echo "🔐 SBOM Monitor - Setup Wizard"
echo "=============================="
echo ""

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "✓ Python $python_version detected"

# Create virtual environment for the monitor script itself
echo ""
echo "📦 Setting up isolated environment for sbom-monitor..."
if [ ! -d "$SCRIPT_DIR/venv-monitor" ]; then
    python3 -m venv "$SCRIPT_DIR/venv-monitor"
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi

# Activate and install dependencies
source "$SCRIPT_DIR/venv-monitor/bin/activate"
echo "✓ Virtual environment activated"

echo "📥 Installing dependencies..."
pip install --quiet --upgrade pip
pip install --quiet pip-audit cyclonedx-bom

echo "✓ Dependencies installed"
deactivate

# Configuration
echo ""
echo "⚙️  Configuration"
echo "=================="

# Get projects directory
read -p "Enter projects root directory (default: ~/projects): " projects_dir
projects_dir=${projects_dir:-~/projects}
projects_dir=$(eval echo "$projects_dir")

if [ ! -d "$projects_dir" ]; then
    echo "⚠️  Directory $projects_dir does not exist"
    read -p "Create it? (y/n): " create_dir
    if [ "$create_dir" = "y" ]; then
        mkdir -p "$projects_dir"
        echo "✓ Created $projects_dir"
    fi
fi

# Get output directory
read -p "Enter output directory for SBOM registry (default: ~/.sbom-monitor): " output_dir
output_dir=${output_dir:-~/.sbom-monitor}
output_dir=$(eval echo "$output_dir")

mkdir -p "$output_dir"
echo "✓ Output directory configured: $output_dir"

# Create config file
config_file="$SCRIPT_DIR/.sbom-monitor.conf"
cat > "$config_file" << EOF
# SBOM Monitor Configuration
# Generated: $(date)

PROJECTS_DIR="$projects_dir"
OUTPUT_DIR="$output_dir"
SCRIPT_PATH="$SCRIPT_PATH"
VENV_PATH="$SCRIPT_DIR/venv-monitor"
SCRIPT_DIR="$SCRIPT_DIR"
EOF

echo "✓ Configuration saved to $config_file"

# Cron setup
echo ""
echo "⏰ Automated Scheduling (optional)"
echo "=================================="
read -p "Set up automated daily runs? (y/n): " setup_cron

if [ "$setup_cron" = "y" ]; then
    read -p "Enter cron time (HH:MM, default: 02:00 for 2 AM): " cron_time
    cron_time=${cron_time:-02:00}

    # Parse hour and minute
    IFS=: read -r cron_hour cron_minute <<< "$cron_time"
    cron_hour=${cron_hour:-02}
    cron_minute=${cron_minute:-00}

    # Create wrapper script
    wrapper_script="$SCRIPT_DIR/run-sbom-monitor.sh"
    cat > "$wrapper_script" << 'WRAPPER_EOF'
#!/bin/bash
# SBOM Monitor Cron Wrapper
source "$(dirname "${BASH_SOURCE[0]}")/.sbom-monitor.conf"
source "$VENV_PATH/bin/activate"
cd "$SCRIPT_DIR"
python "$SCRIPT_PATH" --projects "$PROJECTS_DIR" --output "$OUTPUT_DIR" >> "$OUTPUT_DIR/monitor.log" 2>&1
WRAPPER_EOF

    chmod +x "$wrapper_script"
    echo "✓ Wrapper script created: $wrapper_script"

    # Add to crontab
    cron_entry="$cron_minute $cron_hour * * * $wrapper_script"

    # Check if entry already exists
    if crontab -l 2>/dev/null | grep -q "sbom-monitor"; then
        echo "⚠️  Cron entry already exists"
    else
        (crontab -l 2>/dev/null; echo "$cron_entry") | crontab -
        echo "✓ Cron job scheduled for $cron_time daily"
        echo "  Log file: $output_dir/monitor.log"
    fi
fi

# Test run
echo ""
read -p "Run an initial test scan? (y/n): " run_test

if [ "$run_test" = "y" ]; then
    echo ""
    echo "🚀 Running initial scan..."
    source "$SCRIPT_DIR/venv-monitor/bin/activate"
    cd "$SCRIPT_DIR"
    python "$SCRIPT_PATH" --projects "$projects_dir" --output "$output_dir"
    deactivate
fi

echo ""
echo "✅ Setup complete!"
echo ""
echo "📚 Quick Start:"
echo "  • Run manually:    source '$SCRIPT_DIR/venv-monitor/bin/activate' && python '$SCRIPT_PATH' --projects '$projects_dir' --output '$output_dir'"
echo "  • View report:     open $output_dir/report.html"
echo "  • Check registry:  cat $output_dir/sbom-registry.json"
echo "  • View vulns:      cat $output_dir/vulnerabilities.json"
echo ""
echo "💡 Tips:"
echo "  • Run before major updates to establish a baseline"
echo "  • Check the HTML report for a visual overview"
echo "  • Use --help for advanced options: python $SCRIPT_PATH --help"
echo ""

