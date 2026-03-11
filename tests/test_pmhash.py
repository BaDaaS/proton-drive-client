"""Tests for the PMHash function."""

from proton_drive_client.pmhash import pmhash


def test_pmhash_output_length() -> None:
    """PMHash must produce exactly 256 bytes (2048 bits)."""
    result = pmhash(b"test")
    assert len(result) == 256


def test_pmhash_deterministic() -> None:
    """Same input must produce same output."""
    a = pmhash(b"hello")
    b = pmhash(b"hello")
    assert a == b


def test_pmhash_different_inputs() -> None:
    """Different inputs must produce different outputs."""
    a = pmhash(b"hello")
    b = pmhash(b"world")
    assert a != b


def test_pmhash_empty_input() -> None:
    """Empty input must produce a valid 256-byte output."""
    result = pmhash(b"")
    assert len(result) == 256


def test_pmhash_is_four_sha512() -> None:
    """Verify the construction: 4 concatenated SHA-512 digests."""
    import hashlib

    data = b"test data"
    expected = b""
    for i in range(4):
        expected += hashlib.sha512(data + bytes([i])).digest()

    assert pmhash(data) == expected
