#!/bin/bash

# In-place upgrade script for Netbox Helper Application
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${1:-$SCRIPT_DIR}"
SERVICE_NAME="netbox-importer"
LEGACY_SERVICE="netbox-helper"
DATESTAMP="$(date +%Y%m%d_%H%M%S)"
APP_NAME="$(basename "$APP_DIR")"
PARENT_DIR="$(dirname "$APP_DIR")"
BACKUP_FILE="${PARENT_DIR}/${APP_NAME}_backup_${DATESTAMP}.zip"

# Preserve runtime files that hold server/user/auth state.
PRESERVE_FILES=(
    ".env"
    "settings.json"
    "template-sync/instances.json"
    "template-sync/nbsync_options.json"
)

if [ "$(id -u)" -ne 0 ]; then
    echo "This upgrade script must run as root (or via sudo)."
    exit 1
fi

if [ ! -d "$APP_DIR" ]; then
    echo "App directory not found: $APP_DIR"
    exit 1
fi

if [ ! -d "$APP_DIR/.git" ]; then
    echo "Not a git repository: $APP_DIR"
    exit 1
fi

if [ ! -f "$APP_DIR/setup.sh" ]; then
    echo "Missing setup.sh in $APP_DIR"
    exit 1
fi

verify_service() {
    if ! command -v systemctl >/dev/null 2>&1; then
        echo "systemctl not found; skipping service verification."
        return 0
    fi

    echo "Verifying systemd service: $SERVICE_NAME"

    if ! systemctl list-unit-files --type=service | awk '{print $1}' | grep -Fxq "${SERVICE_NAME}.service"; then
        echo "ERROR: ${SERVICE_NAME}.service is not installed."
        exit 1
    fi

    systemctl daemon-reload

    if ! systemctl is-enabled --quiet "$SERVICE_NAME"; then
        echo "Service is not enabled. Enabling now..."
        systemctl enable "$SERVICE_NAME" >/dev/null
    fi

    if ! systemctl is-active --quiet "$SERVICE_NAME"; then
        echo "Service is not active. Restarting..."
        systemctl restart "$SERVICE_NAME" || true
        sleep 2
    fi

    if ! systemctl is-active --quiet "$SERVICE_NAME"; then
        echo "ERROR: Service failed to start: $SERVICE_NAME"
        echo "Recent logs:"
        journalctl -u "$SERVICE_NAME" -n 40 --no-pager || true
        exit 1
    fi

    WORK_DIR="$(systemctl show -p WorkingDirectory --value "$SERVICE_NAME" 2>/dev/null || true)"
    EXEC_START="$(systemctl show -p ExecStart --value "$SERVICE_NAME" 2>/dev/null || true)"

    if [ "$WORK_DIR" != "$APP_DIR" ]; then
        echo "WARNING: ${SERVICE_NAME} WorkingDirectory is '$WORK_DIR' (expected '$APP_DIR')."
    fi

    if [[ "$EXEC_START" != *"$APP_DIR/.venv/bin/python3"* ]] || [[ "$EXEC_START" != *"netbox_helper.py"* ]]; then
        echo "WARNING: ${SERVICE_NAME} ExecStart looks unexpected:"
        echo "  $EXEC_START"
    fi

    echo "Service verification OK: ${SERVICE_NAME} is enabled and active."
}

echo "Creating backup zip: $BACKUP_FILE"
python3 - "$APP_DIR" "$BACKUP_FILE" <<'PY'
import os
import shutil
import sys

app_dir = os.path.abspath(sys.argv[1])
backup_zip = os.path.abspath(sys.argv[2])
backup_base = backup_zip[:-4] if backup_zip.lower().endswith(".zip") else backup_zip

if os.path.exists(backup_zip):
    raise SystemExit(f"Backup already exists: {backup_zip}")

parent = os.path.dirname(app_dir)
name = os.path.basename(app_dir)
shutil.make_archive(backup_base, "zip", root_dir=parent, base_dir=name)
print(f"Backup created: {backup_zip}")
PY

PRESERVE_DIR="$(mktemp -d)"
cleanup() {
    rm -rf "$PRESERVE_DIR"
}
trap cleanup EXIT

echo "Saving runtime config files..."
for rel_path in "${PRESERVE_FILES[@]}"; do
    src="$APP_DIR/$rel_path"
    if [ -f "$src" ]; then
        mkdir -p "$PRESERVE_DIR/$(dirname "$rel_path")"
        cp -a "$src" "$PRESERVE_DIR/$rel_path"
        echo "  saved: $rel_path"
    fi
done

if command -v systemctl >/dev/null 2>&1; then
    for svc in "$SERVICE_NAME" "$LEGACY_SERVICE"; do
        if systemctl list-unit-files --type=service | awk '{print $1}' | grep -Fxq "${svc}.service"; then
            echo "Stopping service: $svc"
            systemctl stop "$svc" 2>/dev/null || true
        fi
    done
fi

echo "Updating repository to latest default-branch version..."
cd "$APP_DIR"
git fetch origin --prune
git reset --hard

DEFAULT_BRANCH="$(git symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null || true)"
DEFAULT_BRANCH="${DEFAULT_BRANCH#origin/}"
if [ -z "$DEFAULT_BRANCH" ]; then
    DEFAULT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
fi

if ! git show-ref --verify --quiet "refs/remotes/origin/$DEFAULT_BRANCH"; then
    echo "Remote branch not found: origin/$DEFAULT_BRANCH"
    exit 1
fi

git checkout -B "$DEFAULT_BRANCH" "origin/$DEFAULT_BRANCH"
git reset --hard "origin/$DEFAULT_BRANCH"

echo "Restoring runtime config files..."
for rel_path in "${PRESERVE_FILES[@]}"; do
    saved="$PRESERVE_DIR/$rel_path"
    if [ -f "$saved" ]; then
        mkdir -p "$APP_DIR/$(dirname "$rel_path")"
        cp -a "$saved" "$APP_DIR/$rel_path"
        echo "  restored: $rel_path"
    fi
done

echo "Clearing old logs..."
mkdir -p "$APP_DIR/logs"
find "$APP_DIR/logs" -type f -name '*.log' -delete || true
rm -f "$APP_DIR/failures.csv"
: > "$APP_DIR/app.log"
: > "$APP_DIR/netbox_import.log"

echo "Running setup.sh to rebuild .venv and reinstall dependencies..."
chmod +x "$APP_DIR/setup.sh"
"$APP_DIR/setup.sh"
verify_service

echo ""
echo "Upgrade complete."
echo "Backup file: $BACKUP_FILE"
