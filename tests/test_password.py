"""Tests for Proton password hashing."""

from proton_drive_client.password import bcrypt_b64_encode, hash_password


def test_bcrypt_b64_encode_translates_alphabet() -> None:
    """Verify the base64 alphabet translation."""
    # Standard base64 of 0x00 is "AA=="
    # In bcrypt base64, A maps to C (shifted by 2 positions)
    result = bcrypt_b64_encode(b"\x00")
    # The translation should change the characters
    assert result != b"AA=="


def test_hash_password_output_length() -> None:
    """Password hash must produce exactly 256 bytes."""
    result = hash_password(
        password=b"testpassword",
        salt=b"0123456789",
        modulus=b"\x00" * 256,
    )
    assert len(result) == 256


def test_hash_password_deterministic() -> None:
    """Same inputs must produce same output."""
    kwargs = {
        "password": b"mypassword",
        "salt": b"saltsalt00",
        "modulus": b"\xff" * 256,
    }
    a = hash_password(**kwargs)
    b = hash_password(**kwargs)
    assert a == b


def test_hash_password_different_passwords() -> None:
    """Different passwords must produce different hashes."""
    common = {"salt": b"saltsalt00", "modulus": b"\x00" * 256}
    a = hash_password(password=b"password1", **common)
    b = hash_password(password=b"password2", **common)
    assert a != b


def test_hash_password_different_salts() -> None:
    """Different salts must produce different hashes."""
    common = {"password": b"samepassword", "modulus": b"\x00" * 256}
    a = hash_password(salt=b"salt000001", **common)
    b = hash_password(salt=b"salt000002", **common)
    assert a != b
