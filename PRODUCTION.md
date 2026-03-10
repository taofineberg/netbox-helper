# Production Deployment Guide

This guide covers deploying Netbox Helper in production with Gunicorn, SSL, and best practices.

## Table of Contents

1. [Quick Start](#quick-start)
2. [System Requirements](#system-requirements)
3. [Gunicorn Setup](#gunicorn-setup)
4. [SSL/HTTPS Configuration](#sslhttps-configuration)
5. [Reverse Proxy (Nginx)](#reverse-proxy-nginx)
6. [Systemd Service](#systemd-service)
7. [Monitoring & Logging](#monitoring--logging)
8. [Security Hardening](#security-hardening)
9. [Troubleshooting](#troubleshooting)

## Quick Start

### 1. Install Production Dependencies

```bash
cd /opt/netbox-csv-import
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
```

This now includes `gunicorn>=21.0.0` (the WSGI HTTP server for production).

**Note**: The application runs in a virtual environment (`.venv/`) for dependency isolation.

### 2. SSL Configuration (Your Responsibility)

SSL certificates are **not managed by this deployment script**. You must provide your own certificates:

**Options:**
- Commercial CA (Digicert, GlobalSign, Sectigo, etc.)
- Self-signed certificates (testing/internal only)
- Internal PKI
- Other certificate provider (Let's Encrypt, Zerossl, etc.)

Once you have certificates, configure them:

```json
{
  "ssl": {
    "enabled": true,
    "certfile": "/path/to/your/cert.pem",
    "keyfile": "/path/to/your/key.pem"
  }
}
```

See [HTTPS_SETUP.md](HTTPS_SETUP.md) for more details.

### 3. Update Configuration

Edit `settings.json`:

```json
{
  "users": [...],
  "ssl": {
    "enabled": true,
    "certfile": "/etc/ssl/certs/netbox-helper.pem",
    "keyfile": "/etc/ssl/private/netbox-helper.key"
  }
}
```

### 4. Start with Gunicorn

```bash
# Basic (uses gunicorn_config.py)
.venv/bin/gunicorn -c gunicorn_config.py netbox_helper:app

# With environment variables
export PORT=443
export GUNICORN_WORKERS=1
export NBH_SSL_ENABLED=true
export NBH_SSL_CERTFILE=/etc/ssl/certs/netbox-helper.pem
export NBH_SSL_KEYFILE=/etc/ssl/private/netbox-helper.key
.venv/bin/gunicorn -c gunicorn_config.py netbox_helper:app
```

## System Requirements

### Minimum

- **Python**: 3.8+
- **Memory**: 512 MB
- **Disk**: 1 GB
- **CPU**: 2 cores

### Recommended

- **Python**: 3.10+
- **Memory**: 2-4 GB
- **Disk**: 10 GB
- **CPU**: 4+ cores
- **OS**: Ubuntu 20.04 LTS or newer / CentOS 8+

### System Packages

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv
sudo apt-get install -y nginx

# CentOS/RHEL
sudo yum install -y python3 python3-pip
sudo yum install -y nginx
```

## Gunicorn Setup

### Configuration File

The included `gunicorn_config.py` provides production-ready settings:

- **1 worker** (sync) - required for queue correctness
- **120-second timeout** - adjust with `GUNICORN_TIMEOUT`
- **1000-request max** before worker restart - adjust with `GUNICORN_MAX_REQUESTS`
- **Logging** to `logs/gunicorn-access.log` and `logs/gunicorn-error.log`

### Worker Configuration

Use exactly one Gunicorn worker for this application:

```bash
export GUNICORN_WORKERS=1
.venv/bin/gunicorn -c gunicorn_config.py netbox_helper:app
```

Why: CSV import queue/job state is in-process memory. Multiple workers cause split queue state (`No pending jobs`, missing jobs, and inconsistent queue views).

### Running Gunicorn

#### Foreground (Testing)

```bash
.venv/bin/gunicorn -c gunicorn_config.py netbox_helper:app
```

#### Background (Development Only - NOT production!)

```bash
.venv/bin/gunicorn -c gunicorn_config.py \
  --daemon \
  --pidfile /var/run/netbox-helper.pid \
  netbox_helper:app
```

#### Via Systemd (RECOMMENDED)

See the [Systemd Service](#systemd-service) section below.

## SSL/HTTPS Configuration

### Option 1: Gunicorn SSL (Recommended for Simple Setup)

```bash
export NBH_SSL_ENABLED=true
export NBH_SSL_CERTFILE=/etc/ssl/certs/cert.pem
export NBH_SSL_KEYFILE=/etc/ssl/private/key.pem

.venv/bin/gunicorn -c gunicorn_config.py netbox_helper:app
```

### Option 2: Nginx Reverse Proxy SSL (RECOMMENDED for Production)

Use Nginx to handle SSL termination and load balancing. See [Reverse Proxy](#reverse-proxy-nginx) section.

### SSL Certificates (Your Responsibility)

You must provide your own SSL certificates. See [HTTPS_SETUP.md](HTTPS_SETUP.md) for configuration options including:

- Self-signed certificates (testing/internal)
- Commercial Certificate Authorities (Digicert, GlobalSign, Sectigo, etc.)
- Internal PKI
- Other providers

Once you have certificates, place them on the server and configure in `settings.json` or via environment variables.

## Reverse Proxy (Nginx)

For production, use Nginx as a reverse proxy in front of Gunicorn.

### Benefits

- **SSL/TLS termination** (Nginx handles encryption)
- **Load balancing** across separate app instances (if you externalize queue state)
- **Static file serving** (bypass Python)
- **Better performance** and stability

### Basic Nginx Configuration

```nginx
# /etc/nginx/sites-available/netbox-helper

upstream netbox_helper_backend {
    # Gunicorn listening on localhost:8000 (internal)
    server 127.0.0.1:8000;
}

server {
    # HTTP → HTTPS redirect
    listen 80;
    listen [::]:80;
    server_name netbox-helper.example.com;
    
    location / {
        return 301 https://$server_name$request_uri;
    }
}

server {
    # HTTPS
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name netbox-helper.example.com;
    
    # SSL certificates
    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;
    
    # SSL configuration (Mozilla recommended)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Logging
    access_log /var/log/nginx/netbox-helper-access.log;
    error_log /var/log/nginx/netbox-helper-error.log;
    
    # Proxy to Gunicorn
    location / {
        proxy_pass http://netbox_helper_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $server_name;
        proxy_redirect off;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Client upload limit (must match Flask's MAX_CONTENT_LENGTH)
    client_max_body_size 16M;
}
```

### Enable the Configuration

```bash
sudo ln -s /etc/nginx/sites-available/netbox-helper \
  /etc/nginx/sites-enabled/netbox-helper

sudo nginx -t  # Test configuration
sudo systemctl restart nginx
```

### Gunicorn on Internal Port

When using Nginx, run Gunicorn on an internal port (not exposed to internet):

```bash
# gunicorn_config.py will use this
export PORT=8000

# Or in systemd service:
# Environment="PORT=8000"
```

## Systemd Service

Create a systemd service for automatic startup and management.

### Service File

```ini
# /etc/systemd/system/netbox-helper.service

[Unit]
Description=Netbox Helper
After=network.target
Documentation=file:///opt/netbox-csv-import/PRODUCTION.md

[Service]
Type=notify
User=www-data
Group=www-data
WorkingDirectory=/opt/netbox-csv-import

# Environment variables
Environment="PORT=8000"
Environment="GUNICORN_WORKERS=1"
Environment="GUNICORN_TIMEOUT=120"
Environment="NBH_SSL_ENABLED=false"

# Remove these if using Nginx for SSL termination
# Environment="NBH_SSL_ENABLED=true"
# Environment="NBH_SSL_CERTFILE=/etc/ssl/certs/netbox-helper.pem"
# Environment="NBH_SSL_KEYFILE=/etc/ssl/private/netbox-helper.key"

# Start command (using virtual environment)
ExecStart=/opt/netbox-csv-import/.venv/bin/gunicorn -c gunicorn_config.py netbox_helper:app

# Restart policy
Restart=on-failure
RestartSec=10
StartLimitBurst=5
StartLimitIntervalSec=60

# Security
PrivateTmp=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/netbox-csv-import/logs \
  /opt/netbox-csv-import/uploads \
  /opt/netbox-csv-import/settings.json \
  /opt/netbox-csv-import/template-sync/instances.json \
  /opt/netbox-csv-import/template-sync/nbsync_options.json

[Install]
WantedBy=multi-user.target
```

### Install and Start

```bash
# Copy to systemd directory
sudo cp /opt/netbox-csv-import/netbox-helper.service /etc/systemd/system/

# Reload systemd daemon
sudo systemctl daemon-reload

# Enable auto-start on boot
sudo systemctl enable netbox-helper

# Start the service
sudo systemctl start netbox-helper

# Check status
sudo systemctl status netbox-helper

# View logs
sudo journalctl -u netbox-helper -f  # Follow logs
sudo journalctl -u netbox-helper --since "1 hour ago"
```

## Monitoring & Logging

### View Application Logs

```bash
# Recent logs
sudo journalctl -u netbox-helper -n 50

# Real-time logs
sudo journalctl -u netbox-helper -f

# Gunicorn access logs
tail -f logs/gunicorn-access.log

# Gunicorn error logs
tail -f logs/gunicorn-error.log
```

### Monitor Resource Usage

```bash
# Check memory usage
ps aux | grep gunicorn

# Monitor in real-time
watch -n 5 'ps aux | grep gunicorn'
```

### Health Check

```bash
# HTTP health check
curl -k https://localhost/  # With SSL
curl http://localhost:8000/  # Without SSL

# Check application is responding
curl -k https://netbox-helper.example.com/login
```

## Security Hardening

### 1. File Permissions

```bash
# Make settings file readable only by the app user
sudo chown www-data:www-data /opt/netbox-csv-import/settings.json
sudo chmod 600 /opt/netbox-csv-import/settings.json

# Protect private key
sudo chmod 600 /etc/ssl/private/*.key

# Ensure logs are readable
sudo chown -R www-data:www-data /opt/netbox-csv-import/logs
sudo chmod 750 /opt/netbox-csv-import/logs
```

### 2. Firewall

```bash
# UFW (Ubuntu)
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable

# Or just expose Nginx and hide Gunicorn
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
# Don't expose port 8000 (Gunicorn internal)
```

### 3. Environment Variables

Store sensitive data in `/etc/default/netbox-helper`:

```bash
# /etc/default/netbox-helper
SECRET_KEY="your-very-secret-key-here"
APP_PASSWORD="strong-password-123"
GLITCHTIP_DSN="https://..."
```

Then in systemd service:
```ini
EnvironmentFile=/etc/default/netbox-helper
```

### 4. Regular Updates

```bash
# Update packages monthly
.venv/bin/pip install --upgrade -r requirements.txt

# Keep OS updated
sudo apt-get update && sudo apt-get upgrade -y

# Renew certificates (automatic with certbot)
sudo certbot renew
```

### 5. Backup

```bash
# Backup configuration
tar czf netbox-helper-$(date +%Y%m%d).tar.gz \
  /opt/netbox-csv-import/settings.json \
  /opt/netbox-csv-import/template-sync/instances.json

# Backup your SSL certificates
tar czf ssl-certs-$(date +%Y%m%d).tar.gz /etc/ssl/
```

## Troubleshooting

### Gunicorn Won't Start

```bash
# Check syntax error
python3 -m py_compile gunicorn_config.py
python3 -m py_compile netbox_helper.py

# Try running directly
gunicorn -c gunicorn_config.py netbox_helper:app

# Check logs
sudo journalctl -u netbox-helper -n 50
```

### SSL Certificate Errors

```bash
# Verify certificate
openssl x509 -in /path/to/cert.pem -text -noout

# Check key matches certificate
openssl x509 -noout -modulus -in /path/to/cert.pem | openssl md5
openssl rsa -noout -modulus -in /path/to/key.pem | openssl md5
# (Output should match)

# Check expiration
openssl x509 -in /path/to/cert.pem -noout -dates
```

### High Memory Usage

```bash
# Keep worker count at 1 for queue correctness
export GUNICORN_WORKERS=1
export GUNICORN_THREADS=2
sudo systemctl restart netbox-helper

# Monitor memory
watch -n 2 'ps aux --sort=-%mem | head -10'
```

### Nginx Connection Refused

1. Verify Gunicorn is running: `sudo systemctl status netbox-helper`
2. Check Gunicorn is listening on port 8000: `sudo netstat -tuln | grep 8000`
3. Check Nginx configuration: `sudo nginx -t`
4. Verify Nginx is running: `sudo systemctl status nginx`

### Request Timeout

Increase timeout in gunicorn_config.py or environment:
```bash
export GUNICORN_TIMEOUT=300  # 5 minutes
sudo systemctl restart netbox-helper
```

### Performance Issues

1. **Monitor worker load**:
   ```bash
   watch -n 5 'ps aux | grep gunicorn | grep -v grep'
   ```

2. **Tune threads (do not increase workers)**:
   ```bash
   export GUNICORN_WORKERS=1
   export GUNICORN_THREADS=4
   sudo systemctl restart netbox-helper
   ```

3. **Reduce threads if memory > 80%**:
   ```bash
   export GUNICORN_WORKERS=1
   export GUNICORN_THREADS=1
   sudo systemctl restart netbox-helper
   ```

## Next Steps

1. ✅ Install Gunicorn in requirements.txt
2. ✅ Review gunicorn_config.py
3. ✅ Set up SSL certificates
4. ✅ Configure Nginx (optional but recommended)
5. ✅ Create systemd service
6. ✅ Test and deploy
7. ✅ Monitor logs and performance
8. ✅ Plan certificate renewal

For more details, see:
- [HTTPS_SETUP.md](HTTPS_SETUP.md) - SSL certificate setup
- [README.md](README.md) - Application overview
