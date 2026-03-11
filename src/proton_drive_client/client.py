"""
Proton API client.

Handles HTTP communication with the Proton API, including:
- SRP authentication handshake
- Session management (access/refresh tokens)
- PGP key chain unlocking (user -> address -> share -> node)
- Drive API calls (list shares, list/decrypt folders)

The Proton API is not officially documented. Endpoints and request
formats were reverse-engineered from:
- ProtonMail/WebClients (open-source web client)
- henrybear327/Proton-API-Bridge (Go bridge for rclone)
- ProtonMail/proton-python-client (official Python SRP library)
- ProtonMail/go-proton-api (Go API client)

Base URL: https://mail.proton.me/api
"""

from __future__ import annotations

import base64

import requests

from .crypto import (
    PGPPrivateKey,
    decrypt_message,
    decrypt_name,
    unlock_key,
)
from .password import mailbox_password
from .srp import SRPClient

API_BASE = "https://mail.proton.me/api"

# Headers required by the Proton API.
# x-pm-apiversion and x-pm-appversion are mandatory.
# Without them, the server returns 400.
BASE_HEADERS: dict[str, str] = {
    "x-pm-apiversion": "3",
    "x-pm-appversion": "macos-drive@1.0.0-alpha.1+rclone",
    "Accept": "application/vnd.protonmail.v1+json",
    "Content-Type": "application/json",
    "User-Agent": "rclone/v1.65.0",
}


class ProtonClient:
    """
    Proton API client for authentication and Drive access.

    After authentication, call unlock_keys() to decrypt the PGP
    key chain. This enables name decryption in list_children().

    Example:
        client = ProtonClient()
        client.authenticate("user@proton.me", "password")
        client.provide_2fa("123456")  # if 2FA enabled
        client.unlock_keys("password")
        shares = client.list_shares()
        children = client.list_children_decrypted(share_id, link_id)
    """

    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.headers.update(BASE_HEADERS)
        self.uid: str | None = None
        self.access_token: str | None = None
        self.refresh_token: str | None = None

        # PGP key chain (populated by unlock_keys)
        self._user_key: PGPPrivateKey | None = None
        self._address_keys: dict[str, PGPPrivateKey] = {}
        self._share_keys: dict[str, PGPPrivateKey] = {}

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

    def _api_with_fallback(
        self,
        method: str,
        path: str,
        payload: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """Try an API call, falling back to /core/v4/ prefix.

        The Proton API has multiple path schemes depending on
        the endpoint version. Some endpoints work at /path,
        others require /core/v4/path.
        """
        try:
            return self._api(method, path, payload)
        except requests.exceptions.HTTPError as e1:
            print(
                f"  [fallback] {path} -> {e1.response.status_code}"
                f" {e1.response.text[:120]}"
            )
            try:
                return self._api(method, f"/core/v4{path}", payload)
            except requests.exceptions.HTTPError as e2:
                print(
                    f"  [fallback] /core/v4{path} -> "
                    f"{e2.response.status_code}"
                    f" {e2.response.text[:120]}"
                )
                raise

    # ---- Authentication ----

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
        # Step 1: Get SRP parameters
        print(f"[1/4] Requesting auth info for {username}...")
        info = self._api("POST", "/auth/info", {"Username": username})

        salt = base64.b64decode(str(info["Salt"]))
        server_ephemeral = base64.b64decode(str(info["ServerEphemeral"]))
        srp_session = str(info["SRPSession"])
        version = info["Version"]
        modulus = _extract_modulus(str(info["Modulus"]))

        print(f"  SRP version: {version}")
        print(f"  Salt ({len(salt)} bytes): {salt.hex()}")
        print(f"  Modulus ({len(modulus)} bytes): {modulus[:8].hex()}...")

        # Step 2: Compute proof locally
        print("[2/4] Computing SRP proof locally...")
        srp = SRPClient(password, modulus)
        client_ephemeral = srp.get_ephemeral()
        client_proof = srp.process_challenge(salt, server_ephemeral)

        if client_proof is None:
            msg = "SRP challenge failed: invalid server parameters."
            raise ValueError(msg)

        print(f"  Client ephemeral A: {client_ephemeral[:8].hex()}...")
        print(f"  Client proof M1: {client_proof[:8].hex()}...")

        # Step 3: Send proof, get tokens
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

        # Step 4: Verify server proof
        print("[4/4] Verifying server proof (mutual authentication)...")
        server_proof = base64.b64decode(str(auth_resp["ServerProof"]))
        if not srp.verify_server(server_proof):
            msg = "Server proof invalid. Possible MITM attack."
            raise ValueError(msg)

        self._set_session(auth_resp)

        # Check if 2FA is required
        scope = str(auth_resp.get("Scope", ""))
        tfa_info = auth_resp.get("2FA", {})
        tfa_enabled = 0
        if isinstance(tfa_info, dict):
            tfa_enabled = int(tfa_info.get("Enabled", 0))

        if tfa_enabled != 0:
            print()
            print("  2FA is required. Call provide_2fa() with TOTP code.")
        else:
            print()
            print("Authentication successful (no 2FA required).")

        print(f"  UID: {self.uid}")
        print(f"  Scope: {scope}")
        return auth_resp

    def provide_2fa(self, code: str) -> dict[str, object]:
        """
        Submit a TOTP 2FA code to complete authentication.

        After SRP succeeds, Proton may require a second factor.
        POST /auth/2fa with the TOTP code expands the session scope.

        Args:
            code: The 6-digit TOTP code from the authenticator app.

        Returns:
            The /auth/2fa response dict with the expanded scope.
        """
        print("Submitting 2FA code...")
        resp = self._api(
            "POST",
            "/auth/2fa",
            {"TwoFactorCode": code},
        )

        # The 2FA response may contain refreshed tokens.
        # Update the session if new tokens are provided.
        if "AccessToken" in resp:
            self._set_session(resp)

        scope = str(resp.get("Scope", ""))
        print(f"  2FA accepted. Scope: {scope}")
        print(f"  UID: {self.uid}")
        print(f"  Has AccessToken: {'AccessToken' in resp}")
        print(f"  Token prefix: {str(self.access_token)[:12]}...")
        return resp

    def _set_session(self, auth_resp: dict[str, object]) -> None:
        """Store session tokens from an /auth response."""
        self.uid = str(auth_resp["UID"])
        self.access_token = str(auth_resp["AccessToken"])
        self.refresh_token = str(auth_resp["RefreshToken"])
        self.session.headers["x-pm-uid"] = self.uid
        self.session.headers["Authorization"] = f"Bearer {self.access_token}"

    # ---- Key management ----

    def unlock_keys(self, password: str) -> None:
        """
        Unlock the full PGP key chain after authentication.

        This implements the key hierarchy:
        1. GET /keys/salts -> derive mailbox passphrase
        2. GET /users -> unlock user private keys
        3. GET /addresses -> unlock address keys
        4. For each share, unlock the share key on demand

        After calling this, list_children_decrypted() can decrypt
        file and folder names.

        Args:
            password: The user's plaintext password (same as auth).
        """
        password_bytes = password.encode("utf-8")

        # Step 1: Get key salts and derive mailbox passphrase
        #
        # The mailbox passphrase is different from the SRP key.
        # SRP: bcrypt(password, auth_salt + "proton") -> PMHash
        # Mailbox: bcrypt(password, key_salt) -> last 31 bytes
        #
        # The mailbox passphrase unlocks the user's PGP keys.
        print("[keys 1/3] Fetching key salts...")
        salts_resp = self._api_with_fallback("GET", "/keys/salts")
        salts = salts_resp.get("KeySalts", [])
        if not isinstance(salts, list):
            salts = []

        # Build a map of key_id -> decoded salt
        salt_map: dict[str, bytes] = {}
        for entry in salts:
            if not isinstance(entry, dict):
                continue
            key_id = str(entry.get("ID", ""))
            key_salt_b64 = str(entry.get("KeySalt", ""))
            if key_id and key_salt_b64:
                salt_map[key_id] = base64.b64decode(key_salt_b64)

        # Step 2: Get user keys and unlock the primary one
        #
        # User keys are PGP private keys encrypted with the
        # mailbox passphrase. Each user has at least one primary
        # key used to decrypt address key tokens.
        print("[keys 2/3] Unlocking user key...")
        user_resp = self._api_with_fallback("GET", "/users")
        user = user_resp.get("User", {})
        if not isinstance(user, dict):
            msg = "Unexpected /users response format."
            raise ValueError(msg)

        user_keys = user.get("Keys", [])
        if not isinstance(user_keys, list) or not user_keys:
            msg = "No user keys found."
            raise ValueError(msg)

        # Try to unlock the primary user key
        for uk in user_keys:
            if not isinstance(uk, dict):
                continue
            key_id = str(uk.get("ID", ""))
            private_key = str(uk.get("PrivateKey", ""))
            if not private_key:
                continue

            key_salt = salt_map.get(key_id, b"")
            if not key_salt:
                continue

            passphrase = mailbox_password(password_bytes, key_salt)
            try:
                self._user_key = unlock_key(private_key, passphrase)
                print(f"  User key unlocked: {key_id[:16]}...")
                break
            except Exception as e:  # noqa: BLE001
                print(f"  Failed to unlock key {key_id[:16]}: {e}")
                continue

        if self._user_key is None:
            msg = "Could not unlock any user key."
            raise ValueError(msg)

        # Step 3: Get address keys and unlock them
        #
        # Address keys are encrypted differently depending on
        # whether they have a Token field:
        # - With Token: passphrase = decrypt(Token, user_key)
        # - Without Token: passphrase = mailbox_passphrase
        print("[keys 3/3] Unlocking address keys...")
        addr_resp = self._api_with_fallback("GET", "/addresses")
        addresses = addr_resp.get("Addresses", [])
        if not isinstance(addresses, list):
            addresses = []

        for addr in addresses:
            if not isinstance(addr, dict):
                continue
            addr_id = str(addr.get("ID", ""))
            addr_keys = addr.get("Keys", [])
            if not isinstance(addr_keys, list):
                continue

            for ak in addr_keys:
                if not isinstance(ak, dict):
                    continue
                ak_id = str(ak.get("ID", ""))
                ak_private = str(ak.get("PrivateKey", ""))
                ak_token = ak.get("Token")
                if not ak_private:
                    continue

                try:
                    if ak_token and isinstance(ak_token, str):
                        # Decrypt the token with user key to
                        # get the address key passphrase
                        print(f"    Decrypting token for {ak_id[:16]}...")
                        ak_passphrase = decrypt_message(
                            ak_token, self._user_key
                        )
                    else:
                        # Fall back to mailbox passphrase
                        ak_salt = salt_map.get(ak_id, b"")
                        ak_passphrase = mailbox_password(
                            password_bytes, ak_salt
                        )

                    addr_key = unlock_key(ak_private, ak_passphrase)
                    self._address_keys[addr_id] = addr_key
                    print(f"  Address key unlocked: {addr_id[:16]}...")
                    break  # One key per address is enough
                except Exception as e:  # noqa: BLE001
                    import traceback

                    print(
                        f"  Failed to unlock addr key "
                        f"{ak_id[:16]}: "
                        f"{type(e).__name__}: {e}"
                    )
                    traceback.print_exc()
                    continue

        print(f"  {len(self._address_keys)} address key(s) unlocked.")

    def _get_share_key(self, share_id: str) -> PGPPrivateKey:
        """
        Get (and cache) the unlocked share key.

        The share key is a PGP private key whose passphrase is
        encrypted with the address key. To unlock it:
        1. GET /drive/shares/{id} -> Key, Passphrase, AddressID
        2. Decrypt Passphrase with the address key
        3. Unlock Key with the decrypted passphrase

        Args:
            share_id: The share ID.

        Returns:
            The unlocked share PGP key.
        """
        if share_id in self._share_keys:
            return self._share_keys[share_id]

        share_resp = self._api("GET", f"/drive/shares/{share_id}")
        share = share_resp.get("Share", share_resp)
        if not isinstance(share, dict):
            msg = "Unexpected share response format."
            raise ValueError(msg)

        share_key_armored = str(share.get("Key", ""))
        share_passphrase_armored = str(share.get("Passphrase", ""))
        address_id = str(share.get("AddressID", ""))

        if not share_key_armored or not share_passphrase_armored:
            msg = f"Share {share_id[:16]} has no key/passphrase."
            raise ValueError(msg)

        # Find the matching address key
        addr_key = self._address_keys.get(address_id)
        if addr_key is None:
            msg = (
                f"No address key for {address_id[:16]}. "
                f"Call unlock_keys() first."
            )
            raise ValueError(msg)

        # Decrypt the share passphrase with the address key
        share_passphrase = decrypt_message(share_passphrase_armored, addr_key)

        # Unlock the share key
        share_key = unlock_key(share_key_armored, share_passphrase)
        self._share_keys[share_id] = share_key
        return share_key

    def _get_node_key(
        self,
        link: dict[str, object],
        parent_key: PGPPrivateKey,
    ) -> PGPPrivateKey:
        """
        Unlock a node's PGP key using the parent key.

        Each file/folder has:
        - NodeKey: armored PGP private key
        - NodePassphrase: PGP message encrypted with parent key

        For root nodes, parent_key is the share key.
        For children, parent_key is the parent folder's node key.

        Args:
            link: The link dict from the API.
            parent_key: The unlocked parent key.

        Returns:
            The unlocked node PGP key.
        """
        node_key_armored = str(link.get("NodeKey", ""))
        node_passphrase_armored = str(link.get("NodePassphrase", ""))

        if not node_key_armored or not node_passphrase_armored:
            link_id = str(link.get("LinkID", "?"))
            msg = f"Link {link_id[:16]} has no NodeKey."
            raise ValueError(msg)

        # Decrypt the node passphrase with the parent key
        node_passphrase = decrypt_message(node_passphrase_armored, parent_key)

        # Unlock the node key
        return unlock_key(node_key_armored, node_passphrase)

    # ---- Drive API ----

    def list_shares(self) -> list[dict[str, object]]:
        """
        List Drive shares (volumes).

        Each user has a main share. Shared folders are separate
        shares.
        """
        resp = self._api("GET", "/drive/shares")
        shares: list[dict[str, object]] = resp.get(  # type: ignore[assignment]
            "Shares", []
        )
        return shares

    def list_children(
        self, share_id: str, link_id: str
    ) -> list[dict[str, object]]:
        """
        List children of a folder (encrypted names).

        Returns raw API data with encrypted Name fields.
        Use list_children_decrypted() for plaintext names.
        """
        resp = self._api(
            "GET",
            f"/drive/shares/{share_id}/folders/{link_id}/children",
        )
        children: list[dict[str, object]] = resp.get(  # type: ignore[assignment]
            "Links", []
        )
        return children

    def get_link(self, share_id: str, link_id: str) -> dict[str, object]:
        """
        Get a single link (file or folder) by ID.

        This returns the full link metadata including NodeKey
        and NodePassphrase needed for decryption.
        """
        resp = self._api(
            "GET",
            f"/drive/shares/{share_id}/links/{link_id}",
        )
        link: dict[str, object] = resp.get("Link", resp)  # type: ignore[assignment]
        return link

    def list_children_decrypted(
        self, share_id: str, link_id: str
    ) -> list[dict[str, object]]:
        """
        List children of a folder with decrypted names.

        This is the high-level method that:
        1. Gets the share key (cached)
        2. Gets the parent folder's link metadata
        3. Unlocks the parent's node key
        4. Lists children
        5. Decrypts each child's Name field

        The parent node key is needed because Proton encrypts
        child names with the PARENT's key, not the child's own
        key. This means you can list a folder's contents by
        knowing only the parent's key.

        Args:
            share_id: The share ID.
            link_id: The parent folder's link ID.

        Returns:
            List of child link dicts with a "DecryptedName" field.
        """
        if not self._address_keys:
            msg = "Keys not unlocked. Call unlock_keys() first."
            raise ValueError(msg)

        # Get the share key
        share_key = self._get_share_key(share_id)

        # Get the parent folder's metadata to unlock its node key
        parent_link = self.get_link(share_id, link_id)

        # Determine the parent's key: if this is the root folder
        # (ParentLinkID is empty/None), use the share key directly
        # to unlock the node key.
        parent_parent_link_id = parent_link.get("ParentLinkID")
        if not parent_parent_link_id:
            # Root folder: node passphrase encrypted with share key
            parent_node_key = self._get_node_key(parent_link, share_key)
        else:
            # Non-root: we need the grandparent's key.
            # For simplicity, we walk up from the share root.
            parent_node_key = self._resolve_node_key(
                share_id, link_id, share_key
            )

        # List and decrypt children
        children = self.list_children(share_id, link_id)
        for child in children:
            encrypted_name = str(child.get("Name", ""))
            if not encrypted_name:
                child["DecryptedName"] = "(no name)"
                continue
            try:
                child["DecryptedName"] = decrypt_name(
                    encrypted_name, parent_node_key
                )
            except Exception as e:  # noqa: BLE001
                child["DecryptedName"] = f"(decrypt failed: {e})"

        return children

    def _resolve_node_key(
        self,
        share_id: str,
        link_id: str,
        share_key: PGPPrivateKey,
    ) -> PGPPrivateKey:
        """
        Walk from root to the target link, unlocking keys along
        the path.

        Proton's key hierarchy means that to unlock a node key,
        you need its parent's node key. To get the parent's key,
        you need the grandparent's key, and so on up to the root
        (which uses the share key).

        This method fetches the link, walks up to root via
        ParentLinkID, then walks back down unlocking each key.

        Args:
            share_id: The share ID.
            link_id: The target link ID.
            share_key: The unlocked share key.

        Returns:
            The unlocked node key for the target link.
        """
        # Build the path from root to target
        path: list[dict[str, object]] = []
        current_id = link_id
        while current_id:
            link = self.get_link(share_id, current_id)
            path.append(link)
            parent_id = link.get("ParentLinkID")
            if not parent_id or not isinstance(parent_id, str):
                break
            current_id = parent_id

        # path is [target, parent, ..., root]. Reverse it.
        path.reverse()

        # Walk down from root, unlocking each node key
        current_key = share_key
        for node in path:
            current_key = self._get_node_key(node, current_key)

        return current_key


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

    WARNING: This does NOT verify the PGP signature. Production
    code MUST verify against Proton's public key.

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
