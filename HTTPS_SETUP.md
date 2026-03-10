# HTTPS Setup (Clean Version)

This is the short, production-focused guide.

Recommended architecture:
1. Run the app with Gunicorn on internal port `8000`
2. Terminate HTTPS at Nginx or Apache on port `443`
3. Keep SSL certs managed by your existing cert process

## 1. App Service (Common for Nginx and Apache)

The app is already configured to run in `.venv`.

Confirm service is healthy:

```bash
sudo systemctl status netbox-helper
sudo ss -tlnp | grep 8000
```

Expected: `netbox-helper` active and listening on `127.0.0.1:8000` or `0.0.0.0:8000`.

## 2. Nginx HTTPS Setup

Use this when Nginx is your reverse proxy.

Replace all placeholder values (`your-hostname.example.com`, `/path/to/fullchain.pem`, `/path/to/privkey.pem`) with your real hostname and certificate paths.

Create `/etc/nginx/sites-available/netbox-helper`:

```nginx
upstream netbox_helper_backend {
   server 127.0.0.1:8000;
}

server {
   listen 80;
   listen [::]:80;
   server_name your-hostname.example.com;

   return 301 https://$host$request_uri;
}

server {
   listen 443 ssl http2;
   listen [::]:443 ssl http2;
   server_name your-hostname.example.com;

   ssl_certificate /path/to/fullchain.pem;
   ssl_certificate_key /path/to/privkey.pem;

   location / {
      proxy_pass http://netbox_helper_backend;
      proxy_http_version 1.1;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
      proxy_read_timeout 120s;
   }

   client_max_body_size 16M;
}
```

Enable and reload:

```bash
sudo ln -sf /etc/nginx/sites-available/netbox-helper /etc/nginx/sites-enabled/netbox-helper
sudo nginx -t
sudo systemctl reload nginx
```

## 3. Apache HTTPS Setup

Use this when Apache is your reverse proxy.

Replace all placeholder values (`your-hostname.example.com`, `/path/to/fullchain.pem`, `/path/to/privkey.pem`) with your real hostname and certificate paths.

Enable required modules:

```bash
sudo a2enmod ssl proxy proxy_http headers rewrite
```

Create `/etc/apache2/sites-available/netbox-helper.conf`:

```apache
<VirtualHost *:80>
   ServerName your-hostname.example.com
   RewriteEngine On
   RewriteRule ^/(.*)$ https://%{HTTP_HOST}/$1 [R=301,L]
</VirtualHost>

<VirtualHost *:443>
   ServerName your-hostname.example.com

   SSLEngine on
   SSLCertificateFile /path/to/fullchain.pem
   SSLCertificateKeyFile /path/to/privkey.pem

   ProxyPreserveHost On
   RequestHeader set X-Forwarded-Proto "https"
   RequestHeader set X-Forwarded-Port "443"

   ProxyPass / http://127.0.0.1:8000/
   ProxyPassReverse / http://127.0.0.1:8000/

   Timeout 120
</VirtualHost>
```

Enable and reload:

```bash
sudo a2ensite netbox-helper.conf
sudo apache2ctl configtest
sudo systemctl reload apache2
```

## 4. Validate HTTPS

```bash
curl -I http://your-hostname.example.com
curl -kI https://your-hostname.example.com
```

Expected:
1. HTTP returns `301` to HTTPS
2. HTTPS returns `200` (or app login redirect)

## 5. Common Problems

1. `502 Bad Gateway` / `Proxy Error`
  - Check app service: `sudo systemctl status netbox-helper`
  - Check app port: `sudo ss -tlnp | grep 8000`

2. Certificate file errors
  - Verify paths and permissions:

```bash
ls -l /path/to/fullchain.pem /path/to/privkey.pem
```

3. Port conflicts (`80`/`443`)
  - Only one web server should bind each port.
  - If using Nginx, Apache should not listen on `80/443`, and vice versa.

## Notes

1. You normally do not need `NBH_SSL_ENABLED=true` when using Nginx/Apache HTTPS termination.
2. Keep Gunicorn on internal `8000` and expose only `80/443` externally.
3. For full production details, use [PRODUCTION.md](PRODUCTION.md).
