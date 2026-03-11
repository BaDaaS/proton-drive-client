"""
CLI entry point for the Proton Drive client.

Credentials are read from a .env file or environment variables:
    PROTON_USERNAME=user@proton.me
    PROTON_PASSWORD=yourpassword

If not set, the CLI prompts interactively.
2FA code is always prompted interactively (never stored).

Usage:
    uv run python -m proton_drive_client --list-shares
    uv run python -m proton_drive_client --list-folder SHARE_ID LINK_ID
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

import requests

from .client import ProtonClient


def _load_env(env_path: Path) -> None:
    """
    Load variables from a .env file into os.environ.

    Simple parser: each line is KEY=VALUE. Lines starting with #
    are comments. Quotes around values are stripped.
    No external dependency needed.
    """
    if not env_path.exists():
        return
    with env_path.open() as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip("\"'")
            os.environ.setdefault(key, value)


def main() -> None:
    # Load .env from current directory
    _load_env(Path(".env"))

    parser = argparse.ArgumentParser(
        description="Proton Drive API - educational client",
    )
    parser.add_argument(
        "--username",
        default=os.environ.get("PROTON_USERNAME"),
        help="Proton account email (or set PROTON_USERNAME)",
    )
    parser.add_argument(
        "--list-shares",
        action="store_true",
        help="List Drive shares after authentication",
    )
    parser.add_argument(
        "--list-folder",
        nargs=2,
        metavar=("SHARE_ID", "LINK_ID"),
        help="List children of a folder (encrypted names)",
    )
    parser.add_argument(
        "--decrypt",
        action="store_true",
        help="Decrypt file/folder names (requires PGP key chain)",
    )
    args = parser.parse_args()

    # Resolve credentials
    username: str = args.username or input("Username: ")
    password: str = os.environ.get("PROTON_PASSWORD") or getpass.getpass(
        "Password: "
    )

    client = ProtonClient()

    try:
        auth_resp = client.authenticate(username, password)
    except requests.exceptions.HTTPError as e:
        print(f"\nHTTP error: {e.response.status_code}")
        print(f"Response: {e.response.text[:200]}")
        sys.exit(1)
    except ValueError as e:
        print(f"\nAuth error: {e}")
        sys.exit(1)

    # Handle 2FA if required
    tfa_info = auth_resp.get("2FA", {})
    tfa_enabled = 0
    if isinstance(tfa_info, dict):
        tfa_enabled = int(tfa_info.get("Enabled", 0))

    if tfa_enabled != 0:
        code = input("2FA code: ")
        try:
            client.provide_2fa(code)
        except requests.exceptions.HTTPError as e:
            print(f"\n2FA error: {e.response.status_code}")
            print(f"Response: {e.response.text[:200]}")
            sys.exit(1)

    # Unlock PGP key chain if decryption is requested
    if args.decrypt:
        try:
            client.unlock_keys(password)
        except Exception as e:  # noqa: BLE001
            print(f"\nKey unlock error: {e}")
            sys.exit(1)

    if args.list_shares:
        print("\n--- Drive Shares ---")
        try:
            shares = client.list_shares()
            for share in shares:
                print(f"  ShareID: {share.get('ShareID', 'N/A')}")
                print(f"  LinkID:  {share.get('LinkID', 'N/A')}")
                print(f"  Type:    {share.get('Type', 'N/A')}")
                print()
        except requests.exceptions.HTTPError as e:
            print(f"  Error: {e.response.status_code}")
            print(f"  {e.response.text[:200]}")

    if args.list_folder:
        share_id, link_id = args.list_folder

        if args.decrypt:
            # Decrypted listing
            print(f"\n--- Children of {link_id[:16]}... ---")
            try:
                children = client.list_children_decrypted(share_id, link_id)
                for child in children:
                    link_type = child.get("Type", "N/A")
                    type_label = "folder" if link_type == 1 else "file"
                    link_id_val = child.get("LinkID", "N/A")
                    name = str(child.get("DecryptedName", "(unknown)"))
                    print(f"  {type_label}: {name}")
                    print(f"    LinkID: {link_id_val}")
                    print()
            except requests.exceptions.HTTPError as e:
                print(f"  Error: {e.response.status_code}")
                print(f"  {e.response.text[:200]}")
            except ValueError as e:
                print(f"  Error: {e}")
        else:
            # Raw (encrypted) listing
            print(f"\n--- Children of {link_id} ---")
            try:
                children = client.list_children(share_id, link_id)
                for child in children:
                    link_type = child.get("Type", "N/A")
                    link_id_val = child.get("LinkID", "N/A")
                    name = str(child.get("Name", "N/A"))
                    if len(name) > 40:
                        name = name[:40] + "..."
                    print(f"  LinkID: {link_id_val}")
                    print(f"  Type:   {link_type}")
                    print(f"  Name (encrypted): {name}")
                    print()
            except requests.exceptions.HTTPError as e:
                print(f"  Error: {e.response.status_code}")
                print(f"  {e.response.text[:200]}")


if __name__ == "__main__":
    main()
