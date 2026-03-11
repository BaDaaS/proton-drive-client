"""
Proton API client.

Handles HTTP communication with the Proton API, including:
- SRP authentication handshake
- Session management (access/refresh tokens)
- Drive API calls (list shares, list folders)

The Proton API is not officially documented. Endpoints and request
formats were reverse-engineered from:
- ProtonMail/WebClients (open-source web client)
- henrybear327/Proton-API-Bridge (Go bridge for rclone)
- ProtonMail/proton-python-client (official Python SRP library)

Base URL: https://mail.proton.me/api
"""

from __future__ import annotations

import base64

import requests

from .srp import SRPClient

API_BASE = "https://mail.proton.me/api"

# Headers required by the Proton API.
# x-pm-apiversion and x-pm-appversion are mandatory.
# Without them, the server returns 400.
BASE_HEADERS: dict[str, str] = {
    "x-pm-apiversion": "3",
    "x-pm-appversion": "Other",
    "Accept": "application/vnd.protonmail.v1+json",
    "Content-Type": "application/json",
    "User-Agent": "ProtonDriveClient/0.1 (educational)",
}


class ProtonClient:
    """
    Minimal Proton API client for authentication and Drive access.

    Example:
        client = ProtonClient()
        client.authenticate("user@proton.me", "password")
        shares = client.list_shares()
    """

    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.headers.update(BASE_HEADERS)
        self.uid: str | None = None
        self.access_token: str | None = None
        self.refresh_token: str | None = None

    def _api(
        self,
        method: str,
        path: str,
        payload: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """Make an API request and return the JSON response."""
        url = f"{API_BASE}{path}"
        resp: requests.Response
        if method == "GET":
            resp = self.session.get(url, params=payload)  # type: ignore[arg-type]
        elif method == "POST":
            resp = self.session.post(url, json=payload)
        elif method == "DELETE":
            resp = self.session.delete(url)
        else:
            msg = f"Unsupported method: {method}"
            raise ValueError(msg)

        resp.raise_for_status()
        result: dict[str, object] = resp.json()
        return result

    def authenticate(self, username: str, password: str) -> dict[str, object]:
        """
        Authenticate with Proton using SRP.

        Full SRP handshake:
        1. POST /auth/info -> get salt, server ephemeral, modulus
        2. Compute SRP client proof locally (password stays local)
        3. POST /auth -> send ephemeral + proof, get tokens
        4. Verify server proof (mutual authentication)

        Args:
            username: Proton account email.
            password: Account password.

        Returns:
            The full /auth response dict including tokens and scope.

        Raises:
            ValueError: If authentication fails.
            requests.HTTPError: If the API returns an error.
        """
        # ---- Step 1: Get SRP parameters ----
        # The server returns:
        # - Salt: random bytes bound to this user
        # - ServerEphemeral: B = k*v + g^b mod N
        # - Modulus: the prime N, PGP-signed
        # - SRPSession: session identifier for this handshake
        # - Version: auth version (3 or 4)
        print(f"[1/4] Requesting auth info for {username}...")
        info = self._api("POST", "/auth/info", {"Username": username})

        salt = base64.b64decode(str(info["Salt"]))
        server_ephemeral = base64.b64decode(str(info["ServerEphemeral"]))
        srp_session = str(info["SRPSession"])
        version = info["Version"]

        # The modulus is PGP-signed. In production, verify the
        # signature against Proton's public key (fingerprint:
        # 248097092b458509c508dac0350585c4e9518f26).
        modulus = _extract_modulus(str(info["Modulus"]))

        print(f"  SRP version: {version}")
        print(f"  Salt ({len(salt)} bytes): {salt.hex()}")
        print(f"  Modulus ({len(modulus)} bytes): {modulus[:8].hex()}...")

        # ---- Step 2: Compute proof locally ----
        # The password never leaves this machine.
        print("[2/4] Computing SRP proof locally...")
        srp = SRPClient(password, modulus)
        client_ephemeral = srp.get_ephemeral()
        client_proof = srp.process_challenge(salt, server_ephemeral)

        if client_proof is None:
            msg = "SRP challenge failed: invalid server parameters."
            raise ValueError(msg)

        print(f"  Client ephemeral A: {client_ephemeral[:8].hex()}...")
        print(f"  Client proof M1: {client_proof[:8].hex()}...")

        # ---- Step 3: Send proof, get tokens ----
        print("[3/4] Sending proof to server...")
        auth_resp = self._api(
            "POST",
            "/auth",
            {
                "Username": username,
                "ClientEphemeral": base64.b64encode(client_ephemeral).decode(),
                "ClientProof": base64.b64encode(client_proof).decode(),
                "SRPSession": srp_session,
            },
        )

        if "ServerProof" not in auth_resp:
            msg = "Authentication failed. Wrong password or 2FA required."
            raise ValueError(msg)

        # ---- Step 4: Verify server proof ----
        print("[4/4] Verifying server proof (mutual authentication)...")
        server_proof = base64.b64decode(str(auth_resp["ServerProof"]))
        if not srp.verify_server(server_proof):
            msg = "Server proof invalid. Possible MITM attack."
            raise ValueError(msg)

        # Store tokens for subsequent requests
        self.uid = str(auth_resp["UID"])
        self.access_token = str(auth_resp["AccessToken"])
        self.refresh_token = str(auth_resp["RefreshToken"])

        self.session.headers["x-pm-uid"] = self.uid
        self.session.headers["Authorization"] = f"Bearer {self.access_token}"

        print()
        print("Authentication successful.")
        print(f"  UID: {self.uid}")
        print(f"  Scope: {auth_resp.get('Scope', '')}")
        return auth_resp

    # ---- Drive API ----

    def list_shares(self) -> list[dict[str, object]]:
        """
        List Drive shares (volumes).

        Each user has a main share. Shared folders are separate shares.
        """
        resp = self._api("GET", "/drive/shares")
        shares: list[dict[str, object]] = resp.get("Shares", [])  # type: ignore[assignment]
        return shares

    def list_children(
        self, share_id: str, link_id: str
    ) -> list[dict[str, object]]:
        """
        List children of a folder.

        Note: file and folder names are encrypted. The Name field in
        the response is a PGP-encrypted blob that requires the node
        key to decrypt. This demo shows the raw encrypted metadata.
        """
        resp = self._api(
            "GET",
            f"/drive/shares/{share_id}/folders/{link_id}/children",
        )
        children: list[dict[str, object]] = resp.get("Links", [])  # type: ignore[assignment]
        return children


def _extract_modulus(armored: str) -> bytes:
    """
    Extract the modulus from a PGP-signed message.

    The /auth/info endpoint returns the SRP modulus N inside a
    PGP signed message. The structure is:

        -----BEGIN PGP SIGNED MESSAGE-----
        Hash: SHA256

        <base64-encoded modulus>
        -----BEGIN PGP SIGNATURE-----
        ...
        -----END PGP SIGNATURE-----

    WARNING: This does NOT verify the PGP signature. Production code
    MUST verify against Proton's public key to prevent a MITM attack
    where an attacker substitutes a weak modulus.

    Args:
        armored: The full PGP-signed message string.

    Returns:
        The raw 256-byte modulus.
    """
    lines = armored.strip().split("\n")
    content_lines: list[str] = []
    in_content = False

    for line in lines:
        if line.strip() == "" and not in_content:
            in_content = True
            continue
        if line.startswith("-----BEGIN PGP SIGNATURE"):
            break
        if in_content:
            content_lines.append(line.strip())

    modulus_b64 = "".join(content_lines)
    return base64.b64decode(modulus_b64)
