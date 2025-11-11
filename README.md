## Alta User CLI

Helper scripts for Avigilon Alta (formerly Openpath) user administration from the command line. The tool wraps common API workflows such as pulling the user directory, enriching local CSVs with Alta user IDs, and deactivating accounts in bulk.

### Features

- Email/password/TOTP authentication against `/auth/login`.
- `list-users` command with optional pagination control and JSON export.
- `sync-user-ids` command to merge Alta user IDs into an existing CSV by email.
- `deactivate` command to PUT `/orgs/{orgId}/users/{userId}/status` using IDs from a CSV.
- Dry-run support for deactivation, configurable rate limiting, and structured logging.

### Requirements

- Python 3.8+
- `requests` (install via `pip install requests`)

### Quick Start

```bash
python3 -m venv ~/alta-user-env
source ~/alta-user-env/bin/activate
pip install requests
```

Clone or copy the scripts locally, then run commands using an active virtual environment.

### Usage

All commands share the same authentication and connection flags:

- `--org-id` (required): Avigilon Alta organization ID.
- `--base-url`: Override the API base URL (defaults to `https://api.openpath.com`).
- `--email`, `--password`, `--totp`: Credentials for `/auth/login`. Prompts interactively when omitted.
- `--token`: Existing session token to skip login (pass exactly what Alta returns in `data.token`).
- `--timeout`: HTTP timeout (seconds).
- `--verbose`: Enable debug logging.

Environment variables (`ALTA_EMAIL`, `ALTA_PASSWORD`, `ALTA_TOTP`, `ALTA_TOKEN`, `ALTA_BASE_URL`) can provide defaults for the same values.

#### List Users

Fetch users and optionally write them to newline-delimited JSON:

```bash
python alta_user_cli.py --org-id YOUR_ORG_ID list-users --page-size 100 --output ./users.jsonl
```

#### Sync User IDs Into a CSV

Adds or updates a `userID` column by matching Alta users on `user_email` (case-insensitive, handles UTF-8 BOM). Use `--output` to write to a new file or omit to update in place.

```bash
python alta_user_cli.py --org-id YOUR_ORG_ID sync-user-ids --csv /path/to/users.csv
```

Custom columns:

```bash
python alta_user_cli.py --org-id YOUR_ORG_ID sync-user-ids --csv users.csv --email-column emailAddress --user-id-column altaUserId
```

#### Deactivate Users from a CSV

PUT status updates for each `userID` in a CSV. Add `--dry-run` to validate without calling the API.

```bash
python alta_user_cli.py \
  --org-id YOUR_ORG_ID \
  --email you@yourdomain.com \
  --password 'Your Password' \
  --totp 123456 \
  deactivate \
  --csv /path/to/enriched_users.csv \
  --dry-run
```

Remove `--dry-run` when ready for the live update. Use `--sleep <seconds>` to throttle requests if needed.

### Logging

`INFO`-level logs summarize progress, while `--verbose` surfaces request details for troubleshooting. Errors include full API responses to aid debugging.

### Notes

- Multiple users sharing one email address are reported with a warning and the first ID is used.
- Successful status updates may return HTTP 204; the client treats empty bodies as success.
- Keep your CSV backups for auditing before running bulk updates.
- Avigilon, Avigilon Alta, and Openpath are trademarks of Avigilon Corporation. This project is unaffiliated.

### License

Released under the [MIT License](./LICENSE) © 2025 Centre Security LLC.

