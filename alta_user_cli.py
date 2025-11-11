#!/usr/bin/env python3
"""
Command line helper for Avigilon Alta (Openpath) user administration.

Features:
* Authenticate with email, password, and TOTP MFA against /auth/login.
* List users via /orgs/{orgId}/users.
* Deactivate users from a CSV file by issuing PUT /orgs/{orgId}/users/{userId}/status.
* Enrich a CSV with Avigilon Alta user IDs based on email lookups.

Environment variables (optional):
    ALTA_EMAIL        - default email for authentication
    ALTA_PASSWORD     - default password
    ALTA_TOTP         - default TOTP code (usually supplied interactively)
    ALTA_TOKEN        - reuse an existing session token instead of authenticating
    ALTA_BASE_URL     - override API base URL (defaults to https://api.openpath.com)

Requires: requests >= 2.25
"""
from __future__ import annotations

import argparse
import csv
import getpass
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

import requests
from requests import Response, Session
from requests.exceptions import HTTPError


DEFAULT_BASE_URL = "https://api.openpath.com"


class AltaApiError(RuntimeError):
    """Custom exception for unexpected API responses."""


@dataclass
class AltaCredentials:
    email: Optional[str] = None
    password: Optional[str] = None
    totp_code: Optional[str] = None
    token: Optional[str] = None


class AltaClient:
    def __init__(self, base_url: str, org_id: str, credentials: AltaCredentials, timeout: int = 30) -> None:
        self.base_url = base_url.rstrip("/")
        self.org_id = org_id
        self._credentials = credentials
        self.timeout = timeout
        self.session: Session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})
        if credentials.token:
            self._apply_token(credentials.token)

    @property
    def token(self) -> Optional[str]:
        return self.session.headers.get("Authorization")

    def _apply_token(self, token: str) -> None:
        self.session.headers["Authorization"] = token

    def authenticate(self) -> None:
        if self.token:
            logging.debug("Skipping authentication because Authorization header is already set.")
            return

        if not (self._credentials.email and self._credentials.password and self._credentials.totp_code):
            raise AltaApiError("Email, password, and TOTP code are required to authenticate.")

        payload = {
            "email": self._credentials.email,
            "password": self._credentials.password,
            "mfa": {
                "totpCode": self._credentials.totp_code,
            },
        }
        url = f"{self.base_url}/auth/login"
        logging.debug("Authenticating against %s", url)
        response = self.session.post(url, json=payload, timeout=self.timeout)
        self._check_response(response, "authenticate")

        try:
            login_data = response.json()
        except json.JSONDecodeError as exc:
            raise AltaApiError("Login response is not valid JSON.") from exc

        data = login_data.get("data") if isinstance(login_data, dict) else None
        token = data.get("token") if isinstance(data, dict) else None
        if not token:
            raise AltaApiError("Authentication succeeded but no token was returned in response.")

        self._apply_token(token)
        logging.info("Authentication successful; token stored for subsequent requests.")

    def list_users(self, page_size: Optional[int] = None, delay: float = 0.0) -> Iterable[Dict[str, Any]]:
        """
        Iterate over users in the organization, automatically following pagination tokens when provided.

        Args:
            page_size: Optional limit parameter passed through to the API.
            delay: Optional delay (seconds) between paginated requests for rate limiting.
        """
        self.authenticate()
        endpoint = f"{self.base_url}/orgs/{self.org_id}/users"
        next_token: Optional[str] = None

        while True:
            params: Dict[str, Any] = {}
            if page_size:
                params["limit"] = page_size
            if next_token:
                params["pageToken"] = next_token

            logging.debug("Requesting users from %s with params %s", endpoint, params)
            response = self.session.get(endpoint, params=params, timeout=self.timeout)
            self._check_response(response, "list users")
            payload = self._parse_json(response, "list users")

            items = self._extract_data_list(payload)
            for item in items:
                yield item

            meta = payload.get("meta") if isinstance(payload, dict) else {}
            next_token = meta.get("nextPageToken") if isinstance(meta, dict) else None
            if not next_token:
                break
            if delay:
                time.sleep(delay)

    def set_user_status(self, user_id: str, status: str) -> Dict[str, Any]:
        """
        Update a user's status.

        Args:
            user_id: Identifier of the user in Avigilon Alta.
            status: Status value to set (e.g., 'S' to suspend).
        """
        self.authenticate()
        endpoint = f"{self.base_url}/orgs/{self.org_id}/users/{user_id}/status"
        body = {"status": status}
        logging.debug("Sending PUT %s with body %s", endpoint, body)
        response = self.session.put(endpoint, json=body, timeout=self.timeout)
        self._check_response(response, f"set status for user {user_id}")
        return self._parse_json(response, f"set status for user {user_id}")

    def _check_response(self, response: Response, action: str) -> None:
        try:
            response.raise_for_status()
        except HTTPError as exc:
            message = self._format_error_message(response, action)
            raise AltaApiError(message) from exc

    def _format_error_message(self, response: Response, action: str) -> str:
        status = response.status_code
        try:
            details = response.json()
            detail_str = json.dumps(details, indent=2)
        except json.JSONDecodeError:
            detail_str = response.text
        return f"Failed to {action}: HTTP {status}\nResponse: {detail_str}"

    @staticmethod
    def _parse_json(response: Response, action: str) -> Dict[str, Any]:
        if response.status_code == 204 or not response.content:
            return {}
        try:
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError("Response JSON is not an object.")
            return data
        except (json.JSONDecodeError, ValueError) as exc:
            raise AltaApiError(f"Failed to parse JSON for {action}: {exc}") from exc

    @staticmethod
    def _extract_data_list(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        if isinstance(payload, dict) and isinstance(payload.get("data"), list):
            return payload["data"]
        if isinstance(payload, list):
            return payload
        raise AltaApiError("Unexpected response shape; 'data' list not found.")

    @staticmethod
    def extract_user_email(user: Dict[str, Any]) -> Optional[str]:
        if not isinstance(user, dict):
            return None
        identity = user.get("identity")
        if isinstance(identity, dict):
            identity_email = identity.get("email")
            if isinstance(identity_email, str) and identity_email:
                return identity_email
            identity_contact = identity.get("contactInfo")
            if isinstance(identity_contact, dict):
                identity_contact_email = identity_contact.get("email")
                if isinstance(identity_contact_email, str) and identity_contact_email:
                    return identity_contact_email
        for key in ("email", "userEmail", "primaryEmail"):
            value = user.get(key)
            if isinstance(value, str) and value:
                return value
        emails = user.get("emails")
        if isinstance(emails, list):
            for entry in emails:
                if isinstance(entry, dict):
                    for key in ("email", "value"):
                        value = entry.get(key)
                        if isinstance(value, str) and value:
                            return value
                elif isinstance(entry, str) and entry:
                    return entry
        return None


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Manage Avigilon Alta users via API.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--org-id", required=True, help="Organization ID for API requests.")
    parser.add_argument("--base-url", default=os.environ.get("ALTA_BASE_URL", DEFAULT_BASE_URL))
    parser.add_argument("--email", default=os.environ.get("ALTA_EMAIL"), help="Login email (prompts if omitted).")
    parser.add_argument("--password", default=os.environ.get("ALTA_PASSWORD"), help="Login password (prompts if omitted).")
    parser.add_argument("--totp", default=os.environ.get("ALTA_TOTP"), help="6-digit TOTP code (prompts if omitted).")
    parser.add_argument("--token", default=os.environ.get("ALTA_TOKEN"), help="Existing session token; skips login when provided.")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP request timeout in seconds.")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging.")

    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list-users", help="List users in the organization.")
    list_parser.add_argument("--page-size", type=int, help="Optional page size limit.")
    list_parser.add_argument("--delay", type=float, default=0.0, help="Delay (seconds) between paginated requests.")
    list_parser.add_argument(
        "--output",
        help="Optional path to write the user list as JSON (one object per line).",
    )

    deactivate_parser = subparsers.add_parser("deactivate", help="Deactivate users from a CSV file.")
    deactivate_parser.add_argument("--csv", required=True, help="Path to CSV file containing user IDs.")
    deactivate_parser.add_argument(
        "--column",
        default="userId",
        help="CSV column name containing the Avigilon Alta user IDs.",
    )
    deactivate_parser.add_argument(
        "--status",
        default="S",
        help="Status code to apply (default 'S' to suspend/deactivate).",
    )
    deactivate_parser.add_argument(
        "--sleep",
        type=float,
        default=0.0,
        help="Optional sleep (seconds) between API calls to avoid rate limits.",
    )
    deactivate_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate CSV and authentication but skip status updates.",
    )

    sync_parser = subparsers.add_parser(
        "sync-user-ids",
        help="Populate a CSV with Avigilon Alta user IDs based on user email.",
    )
    sync_parser.add_argument("--csv", required=True, help="Path to CSV file to update.")
    sync_parser.add_argument(
        "--email-column",
        default="user_email",
        help="Column in the CSV that contains user email addresses.",
    )
    sync_parser.add_argument(
        "--user-id-column",
        default="userID",
        help="Column name to write the Avigilon Alta user ID into.",
    )
    sync_parser.add_argument(
        "--output",
        help="Optional path for the updated CSV. Defaults to overwriting the input file.",
    )

    return parser.parse_args(argv)


def build_credentials(args: argparse.Namespace) -> AltaCredentials:
    email = args.email or input("Email: ").strip()
    password = args.password or getpass.getpass("Password: ")

    token = args.token
    totp_code: Optional[str] = None
    if token:
        logging.debug("Using provided token; skipping TOTP prompt.")
    else:
        totp_code = args.totp or getpass.getpass("TOTP code: ")

    return AltaCredentials(email=email, password=password, totp_code=totp_code, token=token)


def command_list_users(client: AltaClient, args: argparse.Namespace) -> int:
    users = client.list_users(page_size=args.page_size, delay=args.delay)
    if args.output:
        count = write_users_to_file(users, args.output)
        logging.info("Wrote %s users to %s", count, args.output)
        return 0

    count = 0
    for count, user in enumerate(users, start=1):
        print(json.dumps(user, indent=2))
    logging.info("Retrieved %s users.", count)
    return 0


def write_users_to_file(users: Iterable[Dict[str, Any]], output_path: str) -> int:
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    count = 0
    with open(output_path, "w", encoding="utf-8") as handle:
        for count, user in enumerate(users, start=1):
            handle.write(json.dumps(user))
            handle.write("\n")
    return count


def command_deactivate(client: AltaClient, args: argparse.Namespace) -> int:
    csv_path = os.path.abspath(args.csv)
    if not os.path.isfile(csv_path):
        logging.error("CSV file not found: %s", csv_path)
        return 1

    with open(csv_path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        raw_fieldnames = reader.fieldnames or []
        normalization_map = {normalize_header(name).lower(): name for name in raw_fieldnames}
        normalized_requested_column = normalize_header(args.column).lower()
        column_name = normalization_map.get(normalized_requested_column)
        if not column_name:
            logging.error(
                "CSV header missing '%s'. Available columns: %s",
                args.column,
                ", ".join(raw_fieldnames),
            )
            return 1

        successes = 0
        failures: List[str] = []

        for row in reader:
            user_id = (row.get(column_name) or "").strip()
            if not user_id:
                logging.warning("Skipping row with empty '%s' value: %s", args.column, row)
                continue

            if args.dry_run:
                logging.info("[Dry run] Would set status '%s' for user %s", args.status, user_id)
                successes += 1
                continue

            try:
                client.set_user_status(user_id, args.status)
                logging.info("Set status '%s' for user %s", args.status, user_id)
                successes += 1
            except AltaApiError as exc:
                failures.append(user_id)
                logging.error("Failed to update user %s: %s", user_id, exc)

            if args.sleep:
                time.sleep(args.sleep)

    logging.info("Completed deactivation run. Successes: %s, Failures: %s", successes, len(failures))
    if failures:
        logging.error("User IDs failed to update: %s", ", ".join(failures))
        return 1
    return 0


def command_sync_user_ids(client: AltaClient, args: argparse.Namespace) -> int:
    csv_path = os.path.abspath(args.csv)
    if not os.path.isfile(csv_path):
        logging.error("CSV file not found: %s", csv_path)
        return 1

    target_path = os.path.abspath(args.output) if args.output else csv_path
    temp_path = target_path
    if target_path == csv_path:
        temp_path = f"{csv_path}.tmp"

    temp_dir = os.path.dirname(temp_path)
    if temp_dir:
        os.makedirs(temp_dir, exist_ok=True)

    lookup: Dict[str, str] = {}
    duplicates: Dict[str, List[str]] = {}
    for user in client.list_users():
        if not isinstance(user, dict):
            logging.debug("Skipping unexpected user payload: %s", user)
            continue
        email = AltaClient.extract_user_email(user)
        user_id = user.get("id")
        if not email or not user_id:
            logging.debug("Skipping user without email or id: %s", user)
            continue
        key = email.strip().lower()
        if key in lookup and lookup[key] != str(user_id):
            duplicates.setdefault(key, []).append(str(user_id))
            continue
        lookup[key] = str(user_id)

    if duplicates:
        for email, ids in duplicates.items():
            logging.warning("Multiple user IDs found for %s: %s", email, ", ".join(ids))

    matched = 0
    missing: List[str] = []
    with open(csv_path, newline="", encoding="utf-8") as source, open(
        temp_path,
        "w",
        newline="",
        encoding="utf-8",
    ) as destination:
        reader = csv.DictReader(source)
        raw_fieldnames = reader.fieldnames or []
        normalization_map = {normalize_header(name): name for name in raw_fieldnames}

        normalized_email_header = normalize_header(args.email_column)
        email_column_name = normalization_map.get(normalized_email_header)
        if not email_column_name:
            logging.error(
                "CSV header missing '%s'. Available columns: %s",
                args.email_column,
                ", ".join(raw_fieldnames),
            )
            return 1

        normalized_user_id_header = normalize_header(args.user_id_column)
        user_id_column_name = normalization_map.get(normalized_user_id_header, args.user_id_column)

        fieldnames = list(raw_fieldnames)
        if user_id_column_name not in fieldnames:
            fieldnames.append(user_id_column_name)

        writer = csv.DictWriter(destination, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            email_value = (row.get(email_column_name) or "").strip()
            if not email_value:
                logging.debug("Row missing email in column '%s': %s", args.email_column, row)
                row[user_id_column_name] = ""
                writer.writerow(row)
                continue

            user_id = lookup.get(email_value.lower())
            if user_id:
                matched += 1
                row[user_id_column_name] = user_id
            else:
                row[user_id_column_name] = ""
                missing.append(email_value)
            writer.writerow(row)

    if target_path == csv_path:
        os.replace(temp_path, csv_path)

    logging.info("User ID sync complete. Matched: %s, Missing: %s", matched, len(missing))
    if missing:
        logging.warning("Emails without matching user IDs: %s", ", ".join(sorted(set(missing))))
    if duplicates:
        logging.warning("Duplicate email mappings encountered; review warnings above.")
    return 0


def normalize_header(header: str) -> str:
    if header is None:
        return ""
    return header.lstrip("\ufeff").strip()


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
    )


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    configure_logging(args.verbose)

    credentials = build_credentials(args)
    client = AltaClient(
        base_url=args.base_url,
        org_id=args.org_id,
        credentials=credentials,
        timeout=args.timeout,
    )

    try:
        if args.command == "list-users":
            return command_list_users(client, args)
        if args.command == "deactivate":
            return command_deactivate(client, args)
        if args.command == "sync-user-ids":
            return command_sync_user_ids(client, args)
        raise AltaApiError(f"Unknown command {args.command}")
    except AltaApiError as exc:
        logging.error(str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())

