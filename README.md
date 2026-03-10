# Netbox Helper (Unified)

Netbox Helper is a single web application that combines:

- CSV import into NetBox
- Template compare/sync between NetBox instances
- Zabbix planning and execution for Zabbix-related plugin objects
- Local instance and user administration

The main runtime is `netbox_helper.py`.

## What Is Source of Truth

This is the part that matters most:

- NetBox servers (URL + token) are stored in `template-sync/instances.json`.
- Those servers are managed in the GUI under `Settings -> Netbox Instances`.
- Tokens are encrypted at rest in `instances.json`.
- The unified app does not use `.env` for NetBox URL/token selection.

If a README or old note mentions `NETBOX_URL` / `NETBOX_TOKEN` for the unified flow, ignore it.

## Repository Structure

Primary runtime:

- `netbox_helper.py`: unified Flask app used by systemd service

Core import/sync engines:

- `netbox_importer.py`: CSV parser + import orchestrator
- `api_handlers.py`: per-object NetBox API handler logic
- `nbsync-helper.py`: standalone Zabbix CLI helper script

UI templates:

- `templates/helper_index.html`: unified app UI (CSV Import, Template Sync, Zabbix, Settings)
- `templates/login.html`: unified login page
- `templates/index.html`: legacy CSV-only page used by `app.py`

Persistence files:

- `template-sync/instances.json`: NetBox instances, encrypted tokens
- `template-sync/nbsync_options.json`: persistent Zabbix planner options/rules
- `template-sync/nbxsync-interface-config-context-examples.json`: interface config-context examples
- `settings.json`: local users with hashed passwords

Other runtime artifacts:

- `logs/job_<id>.log`: per-import queue logs
- `netbox_import.log`: stream log used by live terminal panel
- `app.log`: service stdout/stderr target
- `failures.csv`: failed-record retry file

Legacy runtime still in repo:

- `app.py`: older CSV-import-only app (kept for compatibility, not the primary runtime)

## How the Unified App Works

### 1) Authentication

- Users are loaded from `settings.json`.
- Passwords are hashed using Werkzeug.
- On first startup, if no users exist, default `admin / admin` is created.
- Session-based login is required for app routes.

### 2) Instance management

- Instances are created/edited/tested in `Settings` tab.
- Instance tokens are encrypted before save (`enc:` format).
- On startup, existing plaintext tokens are migrated to encrypted form automatically.

### 3) CSV Import engine

- CSV files are parsed by detecting `*-h` header rows.
- Sections are grouped and imported in dependency order:
  - `sites`
  - `locations`
  - `racks`
  - `power-panels`
  - `devices`
  - `power-feeds`
  - `modules`
  - `cables`
  - `power-cables`
  - `vrf`
  - `prefixroles`
  - `prefix`
  - `ip-addresses`
- Queue worker executes pending jobs one at a time.
- Jobs support dry-run, replace, section filtering, delay, and worker count.
- Failures are written to `failures.csv` and can be retried from GUI.

### 4) Template Sync engine

- Compares templates between source and destination instance.
- Produces status buckets:
  - in sync
  - different
  - source only
  - destination only
- Syncs selected items to destination.
- Handles complex template families with component trees:
  - device types
  - module types

### 5) Zabbix planner/executor

- Pulls devices from selected NetBox instance.
- Supports filters:
  - only primary IPv4
  - device type
  - site
  - search by device name
  - optional pull limit
- Builds plan per device:
  - config group assignment
  - tag/hostgroup/macro handling
  - host inventory
  - host interface from config-context
- Can include diff vs current plugin state.
- Supports single-device sync and bulk selected sync.
- Persists planner/rule options in `template-sync/nbsync_options.json`.

## GUI Tabs (Unified App)

The GUI is the intended primary operating model. Most operational tasks should be done in the UI, not by hand-editing files.

### Recommended Operator Flow

1. Go to `Settings` and ensure instances are present and pass `Test`.
2. Use `CSV Import` for structured onboarding/update imports.
3. Use `Template Sync` for controlled cross-instance template drift management.
4. Use `Zabbix` for device-by-device planning, diffing, and sync execution.

### CSV Import

What you see:

- `Target Netbox Server` dropdown.
- Drag/drop upload area.
- Staging table (per-file options).
- Queue table and queue controls.
- Live terminal + error panel + counters.

How to use:

1. Select target server in `Target Netbox Server`.
2. Upload one or more CSV files.
3. For each staged file choose:
   - `Dry Run`
   - `Replace Existing`
   - `Slow Mode` (forces delay and single-thread behavior)
   - `Workers` (when not in slow mode)
   - section checkboxes (auto-detected from file)
4. Click `Add All to Queue`.
5. Click `Run Queue`.
6. Watch live output and counters (`Created`, `Updated`, `Skipped`, `Errors`).

Queue behavior:

- Status values are `pending`, `running`, `done`, `failed`, `stopped`.
- Queue runs sequentially (one job at a time).
- `Stop Current Import` stops the running job and pauses progression.
- `Clear Finished` removes completed/failed/stopped rows from queue.
- `View Log` opens stored job output.

Error handling:

- Failed records are written to `failures.csv`.
- Use `Retry Failures` to retry from failure file.
- Use `Clear Failures` to remove stale failure state.

Back-end endpoints:

- `/upload`
- `/queue` (GET/POST)
- `/queue/start`
- `/queue/<job_id>/remove`
- `/queue/<job_id>/log`
- `/queue/clear`
- `/start-import` (compat route)
- `/stop-import`
- `/get-sections`
- `/retry-failures`
- `/clear-failures`
- `/status`
- `/stream-logs`

### Template Sync

What you see:

- Source and destination selectors.
- Template type chips with multi-select.
- Compare progress bar.
- Summary cards (`In Sync`, `Different`, `Source Only`, `Dest Only`).
- Filtered result table and diff modal.

How to use:

1. Select source and destination instances.
2. Pick template families to include.
3. Click `Compare Instances`.
4. Use top status cards or filter buttons to narrow list.
5. Open per-item diff for changed entries.
6. Select syncable rows and click `Sync Selected -> Destination`.

Notes:

- The summary cards are interactive filters.
- Complex families (device/module types) include component-template comparison.
- Sync actions are explicit per selected row, not automatic.

Back-end endpoints:

- `/sync/api/template-types`
- `/sync/api/compare`
- `/sync/api/sync`

### Zabbix

This tab is the main planner and should be used as a staged workflow: pull -> review -> select -> execute.

What you see:

- Planner inputs:
  - `Target Instance`
  - `Zabbix Server` (auto or explicit)
  - `Config Group`
- Pull options:
  - `Pull device limit`
  - `Only devices with Primary IPv4`
  - `Include diff vs current state`
- Filter row:
  - device type dropdown
  - site dropdown
  - name search
- Metrics row:
  - `Total`, `Visible`, `Selected`, `Types`, `In Sync`, `Not In Sync`, `Diff Pending`, `Cfg Ctx Bad`
- Diff progress bar.
- Dynamic rules editor.
- Device actions table with per-row preview and run buttons.
- Execution results terminal.

Pull/plan workflow:

1. Select `Target Instance`.
2. Select `Config Group` and optionally explicit `Zabbix Server`.
3. Set pull options.
4. Click `Pull Devices`.
5. Filter the result list (type/site/search) as needed.
6. Review per-row preview and diff output before execution.

Dynamic rules section:

- `Use Zabbix Configuration Group inheritance` is enabled by default.
- `Use device tags as Zabbix tags` and `Use device tags as hostgroups` default to off.
- `Source Tags` are read-only and loaded from selected config group.
- `Hostgroup Rules` are editable templated rules.
- `Use Zabbix host inventory` controls inventory push behavior.
- Inventory fields are fully list-driven and persisted.
- Macro list is editable and persisted.
- `Sync config context examples` syncs disabled sample config-context objects into NetBox.

Device actions section:

- Header `Select all / none` checkbox toggles visible row selection.
- Bulk apply toggles (`tags`, `hostgroups`, `macros`, `inventory`) set row flags for selected rows.
- Per-row controls:
  - `Interface` opens parsed host-interface modal for that device.
  - `Sync` runs immediate single-device execution.
- Per-row `Sync` button states:
  - disabled + muted when row is already in sync
  - red when config-context/interface validity indicates likely failure
- Global execution:
  - optional `Dry run`
  - `Execute Selected` for selected device set

Diff and status behavior:

- `Include diff vs current state` defaults to enabled.
- `IN SYNC` is shown only for no-op plans.
- Host-interface hard-fail markers are treated as not-in-sync.
- `Cfg Ctx Bad` counts rows with invalid/missing required interface config-context.

Single-device sync behavior:

- Opens sync progress modal.
- Executes one device.
- Performs verification diff pass for that row.
- Keeps modal open on error so failure details are visible.

Zabbix back-end endpoints:

- `/nbsync/api/options` (GET/PUT)
- `/nbsync/api/interface-example-contexts/sync`
- `/nbsync/api/config-groups`
- `/nbsync/api/servers`
- `/nbsync/api/filter-catalog`
- `/nbsync/api/pull`
- `/nbsync/api/pull-diff-chunk`
- `/nbsync/api/tag`
- `/nbsync/api/execute`
- `/nbsync/api/start` (script mode)
- `/nbsync/api/stop`
- `/nbsync/api/status`
- `/nbsync/api/log`

### Settings

What you see:

- Instance list with `Test`, `Edit`, `Delete`.
- `Add Instance` form.
- User table with user actions.
- Password change panel for current user.

How to use:

1. Add instances with friendly name, URL, and token.
2. Click `Test` on each instance.
3. Use `Edit` to update URL/token.
4. Add additional users as needed.
5. Use `Reset Password` for other users and `Change Your Password` for your account.

Data behavior:

- Instance tokens are encrypted on save.
- User passwords are stored as hashes.

Back-end endpoints:

- `/sync/api/instances` (GET/POST)
- `/sync/api/instances/<id>` (PATCH/DELETE)
- `/sync/api/instances/<id>/test`
- `/settings/api/users` (GET/POST)
- `/settings/api/users/<id>/reset-password`
- `/settings/api/users/<id>` (DELETE)
- `/settings/api/change-password`

## Installation (Clean Install)

Use `setup.sh`.

```bash
cd /opt/netbox-csv-import
chmod +x setup.sh
sudo ./setup.sh
```

What setup does now:

1. Removes existing service units for `netbox-importer` and legacy `netbox-helper`.
2. Rebuilds `.venv` from scratch.
3. Reinstalls dependencies from `requirements.txt`.
4. Installs `netbox-importer.service` pointing to `netbox_helper.py`.
5. Enables and restarts the service.

Service URL default:

- `http://<server-ip>:81`

## Upgrade (In Place)

Use `upgrade.sh` when upgrading an existing `/opt/netbox-csv-import` install.

```bash
cd /opt/netbox-csv-import
chmod +x upgrade.sh
sudo ./upgrade.sh
```

What upgrade does:

1. Creates a dated zip backup in `/opt/`:
   - `netbox-csv-import_backup_YYYYMMDD_HHMMSS.zip`
2. Preserves runtime state files:
   - `.env`
   - `settings.json` (users)
   - `template-sync/instances.json` (NetBox servers)
   - `template-sync/nbsync_options.json`
3. Updates all repository files to latest remote default branch.
4. Clears old logs (`logs/*.log`, `app.log`, `netbox_import.log`, `failures.csv`).
5. Rebuilds `.venv`, reinstalls dependencies, and restarts `netbox-importer`.
6. Verifies `netbox-importer` is installed, enabled, and active (shows service logs on failure).

Optional custom path:

```bash
sudo ./upgrade.sh /path/to/netbox-csv-import
```

## First-Time Bring-Up

After setup:

1. Open the UI and log in with default `admin / admin`.
2. Go to `Settings -> Netbox Instances`.
3. Add each NetBox instance (name, URL, token).
4. Optionally change admin password in Settings.

## Migration from Older Install

For migration to a fresh install, copy only these files:

- users file:
  - from: `<OLD_SETUP_PATH>/settings.json`
  - to: `/opt/netbox-csv-import/settings.json`
- instances file:
  - from: `<OLD_SETUP_PATH>/template-sync/instances.json`
  - to: `/opt/netbox-csv-import/template-sync/instances.json`

Then restart:

```bash
sudo systemctl restart netbox-importer
```

## Configuration

### Unified app runtime `.env`

Used runtime keys:

- `SECRET_KEY`: Flask session secret and token-encryption key derivation
- `PORT`: listen port (default `81`)
- `LOG_LEVEL`: importer logging level
- `LOG_FILE`: importer log file path

Important notes:

- NetBox URL/token are not loaded from `.env` in unified flow.
- Changing `SECRET_KEY` breaks decryption of previously encrypted tokens in `instances.json`.

### About `APP_USERNAME` and `APP_PASSWORD`

- These are legacy values used by `app.py` login path.
- Unified `netbox_helper.py` login uses `settings.json` users, not `.env` username/password.

## Command-Line Usage

### CSV Importer CLI

```bash
source .venv/bin/activate
python netbox_importer.py SLA.csv --instance-id <instance-id> --dry-run
python netbox_importer.py SLA.csv --instance-id <instance-id> --replace
python netbox_importer.py SLA.csv --instance-name "My Instance"
```

### Zabbix helper CLI

```bash
source .venv/bin/activate
python nbsync-helper.py --instance-id <instance-id> --config-group-id 3 --dry-run
python nbsync-helper.py --instance-id <instance-id> --config-group-id 3 --device-name MyDevice
```

## Service Operations

```bash
sudo systemctl status netbox-importer
sudo systemctl restart netbox-importer
sudo systemctl stop netbox-importer
sudo journalctl -u netbox-importer -f
```

## Local Development

Unified app:

```bash
cd /opt/netbox-csv-import
source .venv/bin/activate
PORT=81 python netbox_helper.py
```

Legacy CSV-only app:

```bash
source .venv/bin/activate
PORT=81 python app.py
```

## Troubleshooting

### I can log in but imports/sync cannot connect

Check:

- instances exist in `Settings -> Netbox Instances`
- instance URL is correct and reachable
- token is valid
- instance test endpoint succeeds

### Tokens stopped working after restore

Likely causes:

- `instances.json` restored but `SECRET_KEY` changed
- encrypted tokens came from another environment with different key

Fix:

- restore original `SECRET_KEY`, or
- re-enter tokens in Settings

### Zabbix shows rows not in sync unexpectedly

Check preview/diff and these common reasons:

- missing config-context interface payload
- unresolved Zabbix server selection
- host-interface differences vs current plugin object

### Queue seems idle after stop

This is expected behavior:

- stopping current job pauses further queue progression
- start queue again when ready

## Production Deployment

For production use, this application should be deployed with:

- **Gunicorn** - WSGI HTTP server (replaces Flask dev server)
- **Nginx** - Reverse proxy for SSL/TLS termination and load balancing
- **Systemd** - Service management and auto-restart

The application supports **SSL/TLS via settings.json**, but SSL certificates are your responsibility (external CA, Let's Encrypt, or internal PKI).

### Quick Start

1. **Install production dependencies**:
   ```bash
   pip install -r requirements.txt  # Now includes gunicorn>=21.0.0
   ```

2. **Run automated setup** (recommended):
   ```bash
   sudo bash deploy.sh
   ```
   This script handles:
   - System package installation
   - Application user creation
   - Nginx configuration
   - Systemd service setup

3. **Configure SSL Certificates**:
   - See [HTTPS_SETUP.md](HTTPS_SETUP.md) for certificate configuration options
   - Update `settings.json` with your certificate paths
   - Or use Nginx for SSL termination

4. **Manual deployment**:
   - See [PRODUCTION.md](PRODUCTION.md) for detailed instructions

### Key Files

- `PRODUCTION.md` - Complete production deployment guide
- `HTTPS_SETUP.md` - SSL/HTTPS configuration
- `deploy.sh` - Automated deployment script
- `netbox-helper.service` - Systemd service file template
- `nginx-netbox-helper.conf` - Nginx configuration template
- `gunicorn_config.py` - Gunicorn WSGI server configuration

### Development vs. Production

**Development** (using Flask dev server):
```bash
PORT=81 python netbox_helper.py
```

**Production** (using Gunicorn + Nginx):
```bash
sudo systemctl start netbox-helper
sudo systemctl status netbox-helper
```

### Important Notes

- Flask's development server is **NOT suitable for production**
- When using Nginx, Gunicorn runs on internal port 8000
- Keep `GUNICORN_WORKERS=1` for this app (CSV queue state is in-memory per process)
- SSL/HTTPS configuration is documented in [HTTPS_SETUP.md](HTTPS_SETUP.md)
- For troubleshooting, see the "Troubleshooting" section of [PRODUCTION.md](PRODUCTION.md)

## Security and Git Notes

Sensitive/runtime files are git-ignored, including:

- `.env`
- `template-sync/instances.json`
- `template-sync/nbsync_options.json`
- logs and uploads

This is intentional so credentials and environment state stay local.
