"""
CLI entry point for the Proton Drive client.

Usage:
    uv run python -m proton_drive_client --username user@proton.me
    uv run python -m proton_drive_client --username user@proton.me --list-shares
"""

from __future__ import annotations

import argparse
import getpass
import sys

import requests

from .client import ProtonClient


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Proton Drive API - educational SRP auth demo",
    )
    parser.add_argument(
        "--username",
        required=True,
        help="Proton account email",
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
        help="List children of a folder",
    )
    args = parser.parse_args()

    password = getpass.getpass("Password: ")

    client = ProtonClient()

    try:
        client.authenticate(args.username, password)
    except requests.exceptions.HTTPError as e:
        print(f"\nHTTP error: {e.response.status_code}")
        print(f"Response: {e.response.text[:200]}")
        sys.exit(1)
    except ValueError as e:
        print(f"\nAuth error: {e}")
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
