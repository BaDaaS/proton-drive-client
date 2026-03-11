"""
PGP key management for Proton Drive.

This module implements the minimum OpenPGP operations needed to
decrypt Proton Drive file and folder names. Instead of depending
on a full PGP library, we parse the OpenPGP binary format directly
using only the `cryptography` library for the actual crypto.

This is educational code. A production implementation should use a
proper OpenPGP library. We implement just enough to understand how
Proton's encryption works.

Key hierarchy
-------------
Every piece of data in Proton Drive is encrypted. The keys form
a tree that mirrors the file system structure:

    User Key (unlocked with mailbox passphrase)
        |
        v
    Address Key (unlocked with token decrypted by User Key)
        |
        v
    Share Key (unlocked with passphrase decrypted by Address Key)
        |
        v
    Root Node Key (unlocked with passphrase decrypted by Share Key)
        |
        v
    Child Node Key (unlocked with passphrase decrypted by parent)
        |
        v
    ... (recursive for deeper folders)

Each level follows the same pattern:
    1. A PGP private key is stored (armored) on the server
    2. Its passphrase is stored as a PGP-encrypted message
    3. To unlock a key, you decrypt its passphrase using the
       parent key, then use that passphrase to unlock the key

OpenPGP format primer
---------------------
OpenPGP (RFC 9580) is a packet-based binary format. Every PGP
message or key is a sequence of packets. Each packet has:
    - A tag (1 byte header identifying the type)
    - A length (variable encoding)
    - A body (the payload)

Packet types we handle:
    - Tag 5: Secret Key (primary private key)
    - Tag 7: Secret Subkey (encryption subkey)
    - Tag 1: Public-Key Encrypted Session Key (PKESK)
    - Tag 18: Symmetrically Encrypted Integrity Protected Data (SEIPD)

Source: reverse-engineered from ProtonMail/go-proton-api,
RFC 9580 (OpenPGP), RFC 4880 (original OpenPGP)
"""

from __future__ import annotations

import base64
import hashlib
import struct
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CFB
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap


class _HashConstructor(Protocol):
    def __call__(self) -> hashlib._Hash: ...


# ---- OpenPGP armor parsing ----


def _dearmor(armored: str) -> bytes:
    """
    Strip PGP ASCII armor and return the binary payload.

    ASCII armor wraps binary PGP data in base64 with headers:
        -----BEGIN PGP MESSAGE-----
        <optional headers>

        <base64 data>
        =<checksum>
        -----END PGP MESSAGE-----

    The checksum is a 24-bit CRC (we skip verification here).

    Args:
        armored: ASCII-armored PGP data.

    Returns:
        Raw binary PGP packet data.
    """
    lines = armored.strip().split("\n")
    b64_lines: list[str] = []
    in_body = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("-----BEGIN"):
            continue
        if stripped.startswith("-----END"):
            break
        if not in_body:
            # Skip header lines until blank line
            if stripped == "":
                in_body = True
            continue
        if stripped.startswith("="):
            # CRC checksum line, skip
            break
        b64_lines.append(stripped)

    return base64.b64decode("".join(b64_lines))


# ---- OpenPGP packet parsing ----


def _read_packet(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """
    Read one OpenPGP packet from binary data.

    OpenPGP packet format (new format, bit 6 set):
        Byte 0: 0b11TTTTTT (T = tag, 6 bits)
        Then length encoding:
        - 0-191: 1 byte, value is length
        - 192-8383: 2 bytes, (first-192)*256 + second + 192
        - 255: 4-byte big-endian length follows

    Old format (bit 6 clear):
        Byte 0: 0b10TTTTLL (T = tag 4 bits, L = length type)
        L=0: 1-byte length, L=1: 2-byte, L=2: 4-byte

    Args:
        data: Full binary PGP data.
        offset: Current read position.

    Returns:
        Tuple of (tag, body_bytes, new_offset).
    """
    if offset >= len(data):
        msg = "Unexpected end of PGP data"
        raise ValueError(msg)

    header = data[offset]
    offset += 1

    if header & 0x40:
        # New format packet
        tag = header & 0x3F
        first = data[offset]
        offset += 1

        if first < 192:
            length = first
        elif first < 224:
            second = data[offset]
            offset += 1
            length = ((first - 192) << 8) + second + 192
        elif first == 255:
            length = struct.unpack(">I", data[offset : offset + 4])[0]
            offset += 4
        else:
            # Partial body length (streaming)
            # For simplicity, read all remaining data
            body = data[offset:]
            return tag, body, len(data)
    else:
        # Old format packet
        tag = (header & 0x3C) >> 2
        length_type = header & 0x03

        if length_type == 0:
            length = data[offset]
            offset += 1
        elif length_type == 1:
            length = struct.unpack(">H", data[offset : offset + 2])[0]
            offset += 2
        elif length_type == 2:
            length = struct.unpack(">I", data[offset : offset + 4])[0]
            offset += 4
        else:
            # Indeterminate length: rest of data
            body = data[offset:]
            return tag, body, len(data)

    body = data[offset : offset + length]
    return tag, body, offset + length


def _parse_packets(data: bytes) -> list[tuple[int, bytes]]:
    """Parse all OpenPGP packets from binary data."""
    packets: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        tag, body, offset = _read_packet(data, offset)
        packets.append((tag, body))
    return packets


# ---- S2K (String-to-Key) for key decryption ----


def _s2k_derive(
    passphrase: bytes,
    s2k_type: int,
    hash_algo: int,
    salt: bytes,
    count_coded: int,
    key_len: int,
) -> bytes:
    """
    Derive a symmetric key from a passphrase using OpenPGP S2K.

    S2K (String-to-Key) converts a passphrase into a symmetric
    key for encrypting/decrypting PGP private keys.

    S2K types:
        0 = Simple: H(passphrase)
        1 = Salted: H(salt || passphrase)
        3 = Iterated+Salted: H(salt || passphrase, iterated)

    Proton uses type 3 (iterated and salted) with SHA-256.

    The iteration count is encoded as a single byte:
        count = (16 + (coded & 15)) << ((coded >> 4) + 6)

    Args:
        passphrase: The key passphrase.
        s2k_type: S2K type (0, 1, or 3).
        hash_algo: Hash algorithm ID (8 = SHA-256, 10 = SHA-512).
        salt: 8-byte salt (for types 1 and 3).
        count_coded: Coded iteration count (for type 3).
        key_len: Desired key length in bytes.

    Returns:
        The derived symmetric key.
    """
    hash_fn = {2: "sha1", 8: "sha256", 10: "sha512"}.get(hash_algo, "sha256")

    if s2k_type == 3:
        # Iterated and salted
        count = (16 + (count_coded & 15)) << ((count_coded >> 4) + 6)
        salted = salt + passphrase
        # Repeat salted data until we reach count bytes
        buf = bytearray()
        while len(buf) < count:
            buf.extend(salted)
        data = bytes(buf[:count])
    elif s2k_type == 1:
        data = salt + passphrase
    else:
        data = passphrase

    # Hash with prefix bytes (0x00 * prefix_count) for
    # generating keys longer than the hash output.
    result = b""
    prefix_count = 0
    while len(result) < key_len:
        h = hashlib.new(hash_fn)
        h.update(b"\x00" * prefix_count)
        h.update(data)
        result += h.digest()
        prefix_count += 1

    return result[:key_len]


# ---- X25519 key extraction and decryption ----


class PGPPrivateKey:
    """
    A parsed PGP private key with X25519 subkey for decryption.

    Proton Drive keys are X25519/Ed25519 OpenPGP keys:
    - Primary key: Ed25519 (for signing)
    - Subkey: X25519 (for encryption)

    We only need the X25519 subkey for decryption. The key also
    carries metadata needed for OpenPGP ECDH decryption:
    - fingerprint: the subkey's v4 fingerprint (20 bytes)
    - curve_oid: the curve OID bytes (with length prefix)
    - kdf_hash_id: the KDF hash algorithm ID
    - kek_algo_id: the KEK symmetric algorithm ID
    """

    def __init__(
        self,
        x25519_private: X25519PrivateKey,
        fingerprint: bytes,
        curve_oid: bytes,
        kdf_hash_id: int,
        kek_algo_id: int,
    ) -> None:
        self.x25519_private = x25519_private
        self.fingerprint = fingerprint
        self.curve_oid = curve_oid
        self.kdf_hash_id = kdf_hash_id
        self.kek_algo_id = kek_algo_id


def _ecdh_kdf(
    shared_secret: bytes,
    param: bytes,
    hash_fn: _HashConstructor,
    key_len: int,
) -> bytes:
    """
    OpenPGP ECDH Key Derivation Function.

    KDF(S, param) = Hash(00 00 00 01 || S || param)

    This is a single-pass KDF since the hash output is large
    enough for our key size (SHA-256 -> 32 bytes >= 16 bytes).
    """
    h = hash_fn()
    h.update(b"\x00\x00\x00\x01")
    h.update(shared_secret)
    h.update(param)
    return h.digest()[:key_len]


def _aes_key_unwrap_rfc3394(kek: bytes, wrapped: bytes) -> bytes:
    """
    AES Key Unwrap (RFC 3394).

    This reverses AES Key Wrap, recovering the original key
    from the wrapped form. Used in OpenPGP ECDH to unwrap
    the session key.

    The wrapped data is (n+1)*8 bytes where n is the number
    of 64-bit key data blocks. The first 8 bytes are the IV
    (integrity check value, should be A6A6A6A6A6A6A6A6).

    We use the cryptography library's built-in implementation
    which handles the AES-ECB rounds internally.

    Args:
        kek: Key Encryption Key (16, 24, or 32 bytes).
        wrapped: Wrapped key data.

    Returns:
        The unwrapped key.

    Raises:
        ValueError: If the integrity check fails.
    """
    return aes_key_unwrap(kek, wrapped)


# ---- High-level PGP operations ----


class _ParsedKeyInfo:
    """Result of parsing a secret key packet."""

    def __init__(
        self,
        private_bytes: bytes,
        fingerprint: bytes,
        curve_oid: bytes,
        kdf_hash_id: int,
        kek_algo_id: int,
    ) -> None:
        self.private_bytes = private_bytes
        self.fingerprint = fingerprint
        self.curve_oid = curve_oid
        self.kdf_hash_id = kdf_hash_id
        self.kek_algo_id = kek_algo_id


def _compute_v4_fingerprint(body: bytes, pub_end: int) -> bytes:
    """
    Compute a v4 key fingerprint.

    v4 fingerprint = SHA-1(0x99 || len(pub_body) || pub_body)

    The pub_body is the public portion of the key packet:
    version(1) + creation_time(4) + algo(1) + public_key_material.

    Args:
        body: Full secret key packet body.
        pub_end: Offset where public key material ends.

    Returns:
        20-byte SHA-1 fingerprint.
    """
    pub_body = body[:pub_end]
    h = hashlib.sha1()  # noqa: S324
    h.update(b"\x99")
    h.update(struct.pack(">H", len(pub_body)))
    h.update(pub_body)
    return h.digest()


def _parse_secret_key_packet(
    body: bytes,
    passphrase: bytes,
) -> _ParsedKeyInfo | None:
    """
    Parse a Secret Key or Secret Subkey packet and extract
    the raw private key material plus metadata.

    Packet structure:
        version (1) + creation_time (4) + algo (1) +
        [algo-specific public key material] +
        s2k_usage (1) + [s2k + IV if encrypted] +
        [encrypted private key material]

    For ECDH algo 18 (X25519 for encryption):
        Public key: OID + MPI(public point) + KDF params
        Private key: MPI(secret scalar)

    Args:
        body: Raw packet body bytes.
        passphrase: Passphrase to decrypt the private key.

    Returns:
        _ParsedKeyInfo with private bytes and metadata,
        or None if not an X25519/ECDH key.
    """
    offset = 0

    # Version
    version = body[offset]
    offset += 1

    # Creation time (4 bytes)
    offset += 4

    if version not in (4, 6):
        return None

    # Algorithm
    algo = body[offset]
    offset += 1

    # Track curve OID and KDF params (for ECDH)
    curve_oid = b""
    kdf_hash_id = 0x08  # default SHA256
    kek_algo_id = 0x07  # default AES128

    # Skip public key material based on algorithm
    if algo == 22:
        # EdDSA (Ed25519) - signing key, not what we need
        oid_len = body[offset]
        offset += 1 + oid_len
        mpi_bits = struct.unpack(">H", body[offset : offset + 2])[0]
        mpi_len = (mpi_bits + 7) // 8
        offset += 2 + mpi_len
    elif algo == 18:
        # ECDH (X25519 for encryption)
        # OID (with length prefix)
        oid_len = body[offset]
        curve_oid = body[offset : offset + 1 + oid_len]
        offset += 1 + oid_len
        # MPI (public point)
        mpi_bits = struct.unpack(">H", body[offset : offset + 2])[0]
        mpi_len = (mpi_bits + 7) // 8
        offset += 2 + mpi_len
        # KDF parameters: len(1) + reserved(1) + hash(1) + sym(1)
        kdf_len = body[offset]
        kdf_data = body[offset + 1 : offset + 1 + kdf_len]
        if kdf_len >= 3:
            # kdf_data[0] = reserved (0x01)
            kdf_hash_id = kdf_data[1]
            kek_algo_id = kdf_data[2]
        offset += 1 + kdf_len
    elif algo == 25:
        # X25519 (v6 format, RFC 9580)
        offset += 32
    elif algo == 27:
        # Ed25519 (v6 format, RFC 9580)
        offset += 32
    elif algo in (1, 2, 3):
        # RSA: n MPI + e MPI
        for _ in range(2):
            mpi_bits = struct.unpack(">H", body[offset : offset + 2])[0]
            mpi_len = (mpi_bits + 7) // 8
            offset += 2 + mpi_len
    else:
        return None

    # pub_end marks where public key material ends
    pub_end = offset

    # S2K usage byte
    s2k_usage = body[offset]
    offset += 1

    if s2k_usage == 0:
        # Not encrypted
        secret_data = body[offset:]
    elif s2k_usage in (254, 253, 255):
        # Encrypted with S2K
        if s2k_usage == 253:
            # AEAD encrypted (v6)
            sym_algo = body[offset]
            offset += 1
            aead_algo = body[offset]
            offset += 1
        else:
            sym_algo = body[offset]
            offset += 1
            aead_algo = 0

        s2k_type = body[offset]
        offset += 1
        s2k_hash = body[offset]
        offset += 1

        s2k_salt = b""
        s2k_count = 0

        if s2k_type in (1, 3):
            s2k_salt = body[offset : offset + 8]
            offset += 8
        if s2k_type == 3:
            s2k_count = body[offset]
            offset += 1

        # Determine key length from symmetric algorithm
        key_len = {
            7: 16,  # AES-128
            8: 24,  # AES-192
            9: 32,  # AES-256
        }.get(sym_algo, 16)

        # Derive the symmetric key from the passphrase
        sym_key = _s2k_derive(
            passphrase,
            s2k_type,
            s2k_hash,
            s2k_salt,
            s2k_count,
            key_len,
        )

        if s2k_usage == 253 and aead_algo > 0:
            # AEAD decryption (OCB or GCM)
            # For now, handle GCM (aead_algo 2)
            # and OCB (aead_algo 1, if needed)
            # FIXME: implement AEAD modes if Proton uses v6 keys
            return None

        # CFB mode decryption
        # IV follows the S2K parameters
        iv_len = {7: 16, 8: 16, 9: 16}.get(sym_algo, 16)
        iv = body[offset : offset + iv_len]
        offset += iv_len
        encrypted = body[offset:]

        # Decrypt with AES-CFB
        from cryptography.hazmat.primitives.ciphers import Cipher

        cipher = Cipher(AES(sym_key), CFB(iv))
        decryptor = cipher.decryptor()
        secret_data = decryptor.update(encrypted) + decryptor.finalize()
    else:
        # s2k_usage is the symmetric algorithm ID (old style)
        return None

    # Compute fingerprint from the public key portion
    fingerprint = _compute_v4_fingerprint(body, pub_end)

    # Extract private key material based on algorithm
    if algo == 18:
        # ECDH: MPI of private scalar
        if len(secret_data) < 2:
            return None
        mpi_bits = struct.unpack(">H", secret_data[:2])[0]
        mpi_len = (mpi_bits + 7) // 8
        private_bytes = secret_data[2 : 2 + mpi_len]
        if len(private_bytes) == 32:
            return _ParsedKeyInfo(
                private_bytes,
                fingerprint,
                curve_oid,
                kdf_hash_id,
                kek_algo_id,
            )
        return None
    elif algo == 25:
        # X25519 (v6): 32 bytes directly
        return _ParsedKeyInfo(
            secret_data[:32],
            fingerprint,
            curve_oid,
            kdf_hash_id,
            kek_algo_id,
        )
    else:
        return None


def unlock_key(armored_key: str, passphrase: bytes) -> PGPPrivateKey:
    """
    Parse and unlock a PGP private key.

    Extracts the X25519 encryption subkey from the armored
    private key, decrypts it with the passphrase, and returns
    a PGPPrivateKey that can decrypt messages.

    Args:
        armored_key: ASCII-armored PGP private key.
        passphrase: The passphrase to unlock the key.

    Returns:
        A PGPPrivateKey ready for decryption.

    Raises:
        ValueError: If no X25519 subkey found or decryption fails.
    """
    data = _dearmor(armored_key)
    packets = _parse_packets(data)

    # Look for secret subkey packets (tag 7) with X25519
    # Also check the primary key (tag 5) in case it's X25519
    for tag, body in packets:
        if tag not in (5, 7):
            continue
        info = _parse_secret_key_packet(body, passphrase)
        if info is not None:
            x25519_key = X25519PrivateKey.from_private_bytes(info.private_bytes)
            return PGPPrivateKey(
                x25519_key,
                info.fingerprint,
                info.curve_oid,
                info.kdf_hash_id,
                info.kek_algo_id,
            )

    msg = "No X25519 encryption subkey found in the key."
    raise ValueError(msg)


def decrypt_message(armored_message: str, key: PGPPrivateKey) -> bytes:
    """
    Decrypt a PGP message using a private key.

    Parses the OpenPGP packets:
    1. Find PKESK (tag 1) to get the encrypted session key
    2. Decrypt the session key using our X25519 private key
    3. Find SEIPD (tag 18) or SED (tag 9) for the ciphertext
    4. Decrypt the data with the session key

    Args:
        armored_message: ASCII-armored PGP message.
        key: An unlocked PGPPrivateKey.

    Returns:
        The decrypted plaintext as bytes.
    """
    data = _dearmor(armored_message)
    packets = _parse_packets(data)

    session_key: bytes | None = None
    sym_algo = 0
    encrypted_data: bytes | None = None
    seipd_version = 1

    for tag, body in packets:
        if tag == 1:
            # Public-Key Encrypted Session Key (PKESK)
            _version = body[0]
            # Key ID (8 bytes) or version-specific fields
            # v3: version(1) + keyID(8) + algo(1) + encrypted_key
            key_id = body[1:9]  # noqa: F841
            pk_algo = body[9]
            key_material = body[10:]

            if pk_algo == 18:
                # ECDH
                # MPI of ephemeral point
                mpi_bits = struct.unpack(">H", key_material[:2])[0]
                mpi_len = (mpi_bits + 7) // 8
                ephemeral = key_material[2 : 2 + mpi_len]
                rest = key_material[2 + mpi_len :]
                # Wrapped session key length + data
                wrapped_len = rest[0]
                wrapped = rest[1 : 1 + wrapped_len]

                # Debug: show PKESK details
                our_key_id = key.fingerprint[-8:]
                print(f"    PKESK key_id: {key_id.hex()}")
                print(f"    Our key_id:   {our_key_id.hex()}")
                eph_hex = ephemeral[:8].hex()
                print(f"    Ephemeral ({len(ephemeral)}b): {eph_hex}...")
                print(f"    Wrapped ({len(wrapped)}b): {wrapped[:8].hex()}...")

                # For ECDH, we need to do the full dance
                sym_algo, session_key = _decrypt_ecdh_session_key(
                    key, ephemeral, wrapped
                )
            elif pk_algo == 25:
                # X25519 (v6)
                ephemeral = key_material[:32]
                wrapped = key_material[32:]
                sym_algo, session_key = _decrypt_x25519_session_key(
                    key, ephemeral, wrapped
                )

        elif tag == 18:
            # Symmetrically Encrypted Integrity Protected Data
            seipd_version = body[0]
            encrypted_data = body[1:]

        elif tag == 9:
            # Symmetrically Encrypted Data (older format)
            encrypted_data = body

    if session_key is None:
        msg = "No session key found in message."
        raise ValueError(msg)

    if encrypted_data is None:
        msg = "No encrypted data found in message."
        raise ValueError(msg)

    # Decrypt the data
    return _decrypt_seipd(session_key, sym_algo, encrypted_data, seipd_version)


def _decrypt_ecdh_session_key(
    key: PGPPrivateKey,
    ephemeral_point: bytes,
    wrapped_session_key: bytes,
) -> tuple[int, bytes]:
    """
    Decrypt an ECDH-encrypted session key (RFC 6637).

    X25519 ECDH in OpenPGP:
    1. Sender generates ephemeral keypair (e, E = e*G)
    2. Sender computes S = e * recipient_public
    3. Sender derives KEK = KDF(S, params)
    4. Sender wraps session key with AES Key Wrap
    5. Sends E and wrapped key

    We reverse this:
    1. Compute S = our_private * E (same shared secret)
    2. Derive KEK using the full param block
    3. Unwrap session key

    The KDF param block (RFC 6637, Section 8):
        curve_oid || public_key_algo(1) || 0x03 0x01 ||
        kdf_hash(1) || kek_algo(1) ||
        "Anonymous Sender    " (20 bytes) ||
        recipient_fingerprint (20 bytes for v4)
    """
    # Handle the 0x40 prefix that OpenPGP adds to x25519 points
    if len(ephemeral_point) == 33 and ephemeral_point[0] == 0x40:
        ephemeral_point = ephemeral_point[1:]

    ephemeral_pub = X25519PublicKey.from_public_bytes(ephemeral_point)
    shared_secret = key.x25519_private.exchange(ephemeral_pub)

    # Build the full KDF param block per RFC 6637
    param = (
        key.curve_oid  # OID with length prefix
        + bytes([0x12])  # public key algo 18 (ECDH)
        + bytes([0x03, 0x01])  # KDF params marker
        + bytes([key.kdf_hash_id])  # hash algo
        + bytes([key.kek_algo_id])  # KEK algo
        + b"Anonymous Sender    "  # 20-byte fixed string
        + key.fingerprint  # 20-byte v4 fingerprint
    )

    # Debug: dump intermediate values
    print(f"    ECDH shared_secret: {shared_secret[:8].hex()}...")
    print(f"    curve_oid: {key.curve_oid.hex()}")
    print(f"    kdf_hash: {key.kdf_hash_id:#x}, kek_algo: {key.kek_algo_id:#x}")
    print(f"    fingerprint: {key.fingerprint.hex()}")
    print(f"    KDF param ({len(param)}b): {param.hex()}")

    # Determine hash function and KEK length from key params
    hash_fns: dict[int, _HashConstructor] = {
        0x08: hashlib.sha256,
        0x0A: hashlib.sha512,
    }
    hash_fn = hash_fns.get(key.kdf_hash_id, hashlib.sha256)
    kek_lengths = {
        0x07: 16,  # AES-128
        0x08: 24,  # AES-192
        0x09: 32,  # AES-256
    }
    kek_len = kek_lengths.get(key.kek_algo_id, 16)

    kek = _ecdh_kdf(shared_secret, param, hash_fn, kek_len)
    print(f"    KEK ({len(kek)}b): {kek.hex()}")

    # Unwrap session key
    unwrapped = _aes_key_unwrap_rfc3394(kek, wrapped_session_key)
    sym_algo = unwrapped[0]
    session_key = unwrapped[1:]

    return sym_algo, session_key


def _decrypt_x25519_session_key(
    key: PGPPrivateKey,
    ephemeral: bytes,
    wrapped: bytes,
) -> tuple[int, bytes]:
    """Decrypt a v6 X25519 session key (RFC 9580)."""
    ephemeral_pub = X25519PublicKey.from_public_bytes(ephemeral)
    shared_secret = key.x25519_private.exchange(ephemeral_pub)

    # v6 X25519 uses HKDF-SHA256
    import hmac

    # HKDF-Extract
    prk = hmac.new(b"", shared_secret, hashlib.sha256).digest()
    # HKDF-Expand (single block, 32 bytes)
    okm = hmac.new(prk, b"\x01", hashlib.sha256).digest()

    kek = okm[:16]
    unwrapped = _aes_key_unwrap_rfc3394(kek, wrapped)
    sym_algo = unwrapped[0]
    session_key = unwrapped[1:]

    return sym_algo, session_key


def _decrypt_seipd(
    session_key: bytes,
    sym_algo: int,
    encrypted_data: bytes,
    version: int,
) -> bytes:
    """
    Decrypt Symmetrically Encrypted Integrity Protected Data.

    SEIPD v1 (tag 18, version 1):
        Encrypted with CFB mode. The plaintext starts with:
        - 16 random bytes (block size for AES)
        - 2 bytes: copy of last 2 random bytes (quick check)
        - actual plaintext
        - 20 bytes: SHA-1 MDC (Modification Detection Code)

    The CFB uses a zero IV and the session key.

    Args:
        session_key: The decrypted session key.
        sym_algo: Symmetric algorithm ID (7=AES128, 8=AES192, 9=AES256).
        encrypted_data: The encrypted payload.
        version: SEIPD version (1 or 2).

    Returns:
        The decrypted plaintext.
    """
    if version == 2:
        # SEIPD v2 uses AEAD
        # Parse: sym_algo(1) + aead_algo(1) + chunk_size(1) +
        #        salt(32) + encrypted_chunks
        _v2_sym = encrypted_data[0]
        _v2_aead = encrypted_data[1]
        _v2_chunk = encrypted_data[2]
        _v2_salt = encrypted_data[3:35]
        _v2_ciphertext = encrypted_data[35:]
        # FIXME: implement AEAD decryption for v2
        msg = "SEIPD v2 (AEAD) not yet implemented."
        raise ValueError(msg)

    # Version 1: CFB mode
    from cryptography.hazmat.primitives.ciphers import Cipher

    block_size = 16  # AES block size
    iv = b"\x00" * block_size

    cipher = Cipher(AES(session_key), CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(encrypted_data) + decryptor.finalize()

    # Strip the CFB prefix (block_size + 2 bytes) and MDC (22 bytes)
    # The prefix is: random(block_size) + repeat(2)
    prefix_len = block_size + 2

    # The last 22 bytes are: tag(1) + length(1) + SHA-1(20)
    # (MDC packet, tag 19)
    plaintext = plaintext[prefix_len:-22]

    # The plaintext may contain literal data packets
    return _extract_literal_data(plaintext)


def _extract_literal_data(data: bytes) -> bytes:
    """
    Extract the actual content from a literal data packet.

    Literal Data packet (tag 11):
        format (1) + filename_len (1) + filename (N) +
        date (4) + content

    If the data doesn't start with a valid packet header,
    return it as-is.
    """
    if not data:
        return data

    try:
        packets = _parse_packets(data)
        for tag, body in packets:
            if tag == 11:
                # Literal data packet
                _fmt = body[0]
                fname_len = body[1]
                offset = 2 + fname_len + 4  # skip filename + date
                return body[offset:]
            if tag == 8:
                # Compressed data packet
                algo = body[0]
                compressed = body[1:]
                return _decompress(algo, compressed)
    except (ValueError, IndexError, struct.error):
        pass

    return data


def _decompress(algo: int, data: bytes) -> bytes:
    """Decompress OpenPGP compressed data."""
    if algo == 0:
        return data
    if algo == 1:
        import zlib

        return zlib.decompress(data, -15)
    if algo == 2:
        import zlib

        return zlib.decompress(data)
    if algo == 3:
        import bz2

        return bz2.decompress(data)
    msg = f"Unknown compression algorithm: {algo}"
    raise ValueError(msg)


def decrypt_name(encrypted_name: str, parent_key: PGPPrivateKey) -> str:
    """
    Decrypt a file or folder name.

    Names in Proton Drive are PGP-encrypted with the PARENT
    folder's node key (or the share key for root items).

    Args:
        encrypted_name: The armored PGP message from Link.Name.
        parent_key: The unlocked parent folder's node key.

    Returns:
        The plaintext file/folder name.
    """
    plaintext = decrypt_message(encrypted_name, parent_key)
    return plaintext.decode("utf-8")
