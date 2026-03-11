"""Tests for the SRP client."""

import os

from proton_drive_client.srp import SRPClient, _bytes_to_int, _int_to_bytes


def test_bytes_int_roundtrip() -> None:
    """Little-endian bytes <-> int conversion must roundtrip."""
    original = os.urandom(256)
    n = _bytes_to_int(original)
    result = _int_to_bytes(n, 256)
    assert result == original


def test_srp_client_ephemeral_length() -> None:
    """Client ephemeral A must be 256 bytes."""
    # Use a dummy modulus (not a real prime, just for testing)
    modulus = os.urandom(256)
    srp = SRPClient("testpassword", modulus)
    ephemeral = srp.get_ephemeral()
    assert len(ephemeral) == 256


def test_srp_client_ephemeral_nonzero() -> None:
    """Client ephemeral A must not be all zeros."""
    modulus = os.urandom(256)
    srp = SRPClient("testpassword", modulus)
    ephemeral = srp.get_ephemeral()
    assert ephemeral != b"\x00" * 256


def test_srp_rejects_zero_server_ephemeral() -> None:
    """process_challenge must reject B = 0 (security check)."""
    modulus = os.urandom(256)
    srp = SRPClient("testpassword", modulus)
    salt = os.urandom(10)
    # B = 0 means the server is broken or malicious
    result = srp.process_challenge(salt, b"\x00" * 256)
    assert result is None
