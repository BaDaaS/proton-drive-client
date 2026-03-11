"""
Proton password hashing.

How Proton derives the SRP private key from a password
------------------------------------------------------
SRP requires a private key x derived from the user's password and a
salt. The derivation must be slow (to resist brute-force) and produce
a value matching the modulus size (2048 bits).

Proton's approach (auth version 3/4):

    1. Prepare the bcrypt salt:
       - Take the server-provided salt (10 bytes)
       - Append the literal string "proton"
       - Truncate to 16 bytes
       - Re-encode from standard base64 to bcrypt's base64 alphabet
       - Take 22 characters (bcrypt expects 22-char salt)

    2. bcrypt the password:
       - Use cost factor 10 (2^10 = 1024 iterations)
       - This is the slow step that resists brute-force

    3. Expand to 2048 bits:
       - Concatenate the bcrypt output with the modulus N
       - Hash with PMHash to get 256 bytes

Why "proton" in the salt?
-------------------------
The server sends a 10-byte random salt. Proton appends "proton" before
truncating to 16 bytes. This is a domain separation technique: even if
another service used the same salt value, the derived key would differ
because of the "proton" suffix. It also extends short salts to the
16 bytes that bcrypt base64 encoding expects.

Why re-encode to bcrypt base64?
-------------------------------
bcrypt uses a non-standard base64 alphabet. The characters ./A-Za-z0-9
replace the standard A-Za-z0-9+/ ordering. The re-encoding translates
between the two alphabets so that the binary salt is correctly
interpreted by the bcrypt implementation.

Source: reverse-engineered from ProtonMail/proton-python-client
"""

import base64

import bcrypt

from .pmhash import pmhash

# bcrypt uses a different base64 alphabet than standard base64.
# Standard: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
# bcrypt:   ./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789
_STD_B64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_BCRYPT_B64 = (
    b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)
_B64_TRANSLATION = bytes.maketrans(_STD_B64, _BCRYPT_B64)


def bcrypt_b64_encode(data: bytes) -> bytes:
    """
    Re-encode standard base64 to bcrypt's base64 alphabet.

    bcrypt uses ./A-Za-z0-9 instead of the standard A-Za-z0-9+/.
    This function takes raw bytes, encodes them in standard base64,
    then translates to bcrypt's alphabet.

    Args:
        data: Raw bytes to encode.

    Returns:
        bcrypt-base64 encoded bytes.
    """
    return base64.b64encode(data).translate(_B64_TRANSLATION)


def hash_password(
    password: bytes,
    salt: bytes,
    modulus: bytes,
) -> bytes:
    """
    Derive the SRP private key x from a password.

    This implements Proton's password hashing scheme (version 3/4):
    bcrypt(password, prepared_salt) -> PMHash(bcrypt_out || modulus)

    Args:
        password: The user's password as UTF-8 bytes.
        salt: The 10-byte salt from the server (/auth/info response).
        modulus: The 256-byte SRP modulus N.

    Returns:
        256 bytes (2048 bits) suitable as the SRP private key x.
    """
    # Step 1: Prepare the bcrypt salt
    #   salt = server_salt + "proton", truncated to 16 bytes
    #   Then base64-encode for bcrypt (22 chars)
    padded_salt = (salt + b"proton")[:16]
    bcrypt_salt = bcrypt_b64_encode(padded_salt)[:22]

    # Step 2: bcrypt with cost factor 10
    #   This is intentionally slow (~100ms) to resist offline attacks.
    #   The $2y$ prefix selects the bcrypt variant that handles
    #   8-bit characters correctly.
    hashed = bcrypt.hashpw(password, b"$2y$10$" + bcrypt_salt)

    # Step 3: Expand to 2048 bits with PMHash
    #   The bcrypt output (~60 bytes) is too short for SRP.
    #   PMHash(bcrypt_output || modulus) gives us 256 bytes.
    #   Including the modulus in the hash binds the key to this
    #   specific SRP group, preventing cross-group attacks.
    return pmhash(hashed + modulus)


def mailbox_password(password: bytes, key_salt: bytes) -> bytes:
    """
    Derive the mailbox passphrase used to unlock PGP private keys.

    This is different from hash_password() which derives the SRP
    private key x. The mailbox passphrase unlocks the user's actual
    PGP keys stored on Proton's servers.

    Steps:
        1. Encode key_salt with bcrypt's base64 alphabet (22 chars)
        2. bcrypt(password, "$2y$10$" + encoded_salt)
        3. Take the last 31 bytes of the bcrypt output string

    Why 31 bytes?
        bcrypt output is 60 bytes: "$2y$10$" (7) + salt (22) + hash (31).
        The first 29 bytes are the prefix and salt, the remaining 31
        bytes are the actual hash output that serves as the passphrase.

    Source: ProtonMail/go-srp hash.go MailboxPassword()

    Args:
        password: The user's password as UTF-8 bytes.
        key_salt: The key salt from /keys/salts (base64-decoded).

    Returns:
        31 bytes to use as the PGP key passphrase.
    """
    bcrypt_salt = bcrypt_b64_encode(key_salt)[:22]
    hashed = bcrypt.hashpw(password, b"$2y$10$" + bcrypt_salt)
    return hashed[29:]
