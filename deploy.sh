#!/bin/bash
# Quick production deployment setup script for Netbox Helper
# Usage: sudo bash deploy.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${APP_DIR:-$SCRIPT_DIR}"
APP_USER="www-data"
APP_GROUP="www-data"

echo "=========================================="
echo "Netbox Helper Production Deployment Setup"
echo "=========================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root or with sudo"
   exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot determine OS"
    exit 1
fi

echo ""
echo "Detected OS: $OS"

# Install system dependencies
echo ""
echo "Installing system dependencies..."
if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    apt-get update
    apt-get install -y python3 python3-pip python3-venv
    apt-get install -y nginx
    apt-get install -y curl wget
elif [ "$OS" = "centos" ] || [ "$OS" = "rhel" ]; then
    yum groupinstall -y "Development Tools"
    yum install -y python3 python3-pip
    yum install -y nginx
    yum install -y curl wget
else
    echo "Unsupported OS. Please install dependencies manually."
fi

# Create application user if it doesn't exist
if ! id "$APP_USER" &>/dev/null; then
    echo ""
    echo "Creating application user: $APP_USER"
    useradd -r -s /bin/bash $APP_USER
else
    echo "Application user $APP_USER already exists"
fi

# Install Python dependencies
echo ""
echo "Installing Python dependencies..."
cd "$APP_DIR"
pip3 install --upgrade pip setuptools wheel
pip3 install -r requirements.txt
echo "✓ Python dependencies installed"

# Create necessary directories
echo ""
echo "Creating application directories..."
mkdir -p "$APP_DIR/logs"
mkdir -p "$APP_DIR/uploads"
chown -R $APP_USER:$APP_GROUP "$APP_DIR/logs"
chown -R $APP_USER:$APP_GROUP "$APP_DIR/uploads"
echo "✓ Directories created and permissions set"

# Set file permissions
echo ""
echo "Setting file permissions..."
chown $APP_USER:$APP_GROUP "$APP_DIR/settings.json"
chmod 600 "$APP_DIR/settings.json"
chown -R $APP_USER:$APP_GROUP "$APP_DIR/template-sync"
chmod 750 "$APP_DIR/template-sync"
echo "✓ File permissions configured"

# Install systemd service
echo ""
echo "Installing systemd service..."
cp "$APP_DIR/netbox-helper.service" /etc/systemd/system/
systemctl daemon-reload
echo "✓ Systemd service installed"

# Configure Nginx (optional)
read -p "Do you want to configure Nginx as reverse proxy? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Setting up Nginx..."
    
    # Get domain name
    read -p "Enter your domain name (e.g., netbox-helper.example.com): " DOMAIN
    
    # Copy Nginx config
    sed "s/netbox-helper.example.com/$DOMAIN/g" "$APP_DIR/nginx-netbox-helper.conf" > /etc/nginx/sites-available/netbox-helper
    
    # Enable site
    if [ ! -f /etc/nginx/sites-enabled/netbox-helper ]; then
        ln -s /etc/nginx/sites-available/netbox-helper /etc/nginx/sites-enabled/
    fi
    
    # Test Nginx config
    nginx -t
    
    # Reload Nginx
    systemctl reload nginx
    
    echo ""
    echo "✓ Nginx configured for reverse proxy"
    echo ""
    echo "IMPORTANT: SSL Configuration"
    echo "================================"
    echo "Nginx is configured to expect SSL certificates."
    echo "Please provide your own SSL certificates before accessing via HTTPS."
    echo "See HTTPS_SETUP.md for certificate configuration options."
else
    echo "Skipping Nginx setup. You can configure it manually later."
fi

# Start service
echo ""
echo "Starting Netbox Helper service..."
systemctl enable netbox-helper
systemctl start netbox-helper
systemctl status netbox-helper

echo ""
echo "=========================================="
echo "✓ Deployment Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Configure SSL certificates (see HTTPS_SETUP.md)"
echo "2. Monitor logs: sudo journalctl -u netbox-helper -f"
echo "3. Check status: sudo systemctl status netbox-helper"
echo "4. View Nginx logs: tail -f /var/log/nginx/netbox-helper-*.log"
echo ""
echo "For more information, see:"
echo "  - PRODUCTION.md - Complete production deployment guide"
echo "  - HTTPS_SETUP.md - SSL/HTTPS configuration"
echo "  - README.md - Application overview"
