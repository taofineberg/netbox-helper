#!/bin/bash

# Setup script for Netbox Helper Application
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="netbox-importer"
LEGACY_SERVICES=("netbox-importer" "netbox-helper")
SYSTEMD_DIR="/etc/systemd/system"
APP_USER="root"
APP_GROUP="root"

if [ "$(id -u)" -ne 0 ]; then
    echo "This setup script must run as root (or via sudo)."
    exit 1
fi

remove_existing_service() {
    local svc="$1"
    local unit="${svc}.service"
    local unit_path="${SYSTEMD_DIR}/${unit}"
    local exists=0

    if [ -f "$unit_path" ]; then
        exists=1
    elif systemctl list-unit-files --type=service | awk '{print $1}' | grep -Fxq "$unit"; then
        exists=1
    fi

    if [ "$exists" -eq 1 ]; then
        echo "Removing existing system service: $unit"
        systemctl stop "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
        rm -f "$unit_path"
    fi
}

echo "Starting clean setup for Netbox Helper..."

echo "Cleaning previous system app services..."
for svc in "${LEGACY_SERVICES[@]}"; do
    remove_existing_service "$svc"
done
systemctl daemon-reload

echo "Rebuilding Python virtual environment for clean install..."
rm -rf "$APP_DIR/.venv"
python3 -m venv "$APP_DIR/.venv"

echo "Installing dependencies..."
"$APP_DIR/.venv/bin/pip" install --upgrade pip --quiet
"$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt" --quiet
echo "Dependencies installed."

if [ ! -f "$APP_DIR/.env" ]; then
    echo ""
    echo "=== App Login Credentials ==="
    read -rp "App username [admin]: " APP_USERNAME
    APP_USERNAME="${APP_USERNAME:-admin}"
    read -rsp "App password [admin]: " APP_PASSWORD
    APP_PASSWORD="${APP_PASSWORD:-admin}"
    echo ""

    SECRET_KEY=$("$APP_DIR/.venv/bin/python3" -c "import secrets; print(secrets.token_hex(32))")

    cat > "$APP_DIR/.env" <<EOF
LOG_LEVEL=INFO
LOG_FILE=netbox_import.log
SECRET_KEY=${SECRET_KEY}
APP_USERNAME=${APP_USERNAME}
APP_PASSWORD=${APP_PASSWORD}
PORT=81
EOF
    echo ".env created."
else
    echo ".env already exists, keeping current values."
fi

echo "Preparing runtime files and permissions..."
mkdir -p "$APP_DIR/data" "$APP_DIR/uploads" "$APP_DIR/logs" "$APP_DIR/template-sync"
touch "$APP_DIR/app.log" "$APP_DIR/netbox_import.log"
if [ ! -f "$APP_DIR/settings.json" ]; then
    if [ -f "$APP_DIR/settings.example.json" ]; then
        cp "$APP_DIR/settings.example.json" "$APP_DIR/settings.json"
    else
        echo '{"users":[]}' > "$APP_DIR/settings.json"
    fi
fi
if [ ! -f "$APP_DIR/template-sync/instances.json" ]; then
    echo '{"instances":[]}' > "$APP_DIR/template-sync/instances.json"
fi
chown -R "$APP_USER:$APP_GROUP" \
    "$APP_DIR/uploads" \
    "$APP_DIR/logs" \
    "$APP_DIR/template-sync" \
    "$APP_DIR/app.log" \
    "$APP_DIR/netbox_import.log" \
    "$APP_DIR/settings.json" \
    "$APP_DIR/template-sync/instances.json"

echo "Installing systemd service..."
cat > "${SYSTEMD_DIR}/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Netbox Helper Web App
After=network.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/.venv/bin/python3 -u netbox_helper.py
User=root
Group=root
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
Restart=always
RestartSec=5
StandardOutput=append:${APP_DIR}/app.log
StandardError=append:${APP_DIR}/app.log

[Install]
WantedBy=multi-user.target
EOF

APP_PORT=$(grep -E '^PORT=' "$APP_DIR/.env" 2>/dev/null | tail -n1 | cut -d= -f2 || true)
APP_PORT="${APP_PORT:-81}"
if ss -tln 2>/dev/null | grep -q ":${APP_PORT} "; then
    echo ""
    echo "ERROR: Port ${APP_PORT} is already in use."
    echo "Update PORT in $APP_DIR/.env, then run:"
    echo "  systemctl restart ${SERVICE_NAME}"
    exit 1
fi

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"

echo ""
echo "If migrating from an old setup, copy ONLY these files from the old install:"
echo "  1) users:   <OLD_SETUP_PATH>/settings.json"
echo "     -> ${APP_DIR}/settings.json"
echo "  2) servers: <OLD_SETUP_PATH>/template-sync/instances.json"
echo "     -> ${APP_DIR}/template-sync/instances.json"
echo ""
echo "Bundled sanitized CSV templates are included for clean installs:"
echo "  - ${APP_DIR}/data/Netbox-import.csv"
echo "  - ${APP_DIR}/data/Reference-template.csv"
echo "These are safe starter/reference files and can be replaced later if needed."
echo ""

sleep 2
if systemctl is-active --quiet "${SERVICE_NAME}"; then
    echo "Setup complete."
    echo "Web app is running at http://$(hostname -I | awk '{print $1}'):${APP_PORT}"
    echo ""
    echo "Useful commands:"
    echo "  systemctl status ${SERVICE_NAME}   - check status"
    echo "  systemctl restart ${SERVICE_NAME}  - restart"
    echo "  journalctl -u ${SERVICE_NAME} -f   - follow logs"
else
    echo "WARNING: Service failed to start. Check logs:"
    echo "  journalctl -u ${SERVICE_NAME} -n 20"
fi
