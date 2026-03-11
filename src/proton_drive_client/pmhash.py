"""
PMHash: Proton's custom 2048-bit hash function.

Why does this exist?
--------------------
SRP (Secure Remote Password) performs arithmetic modulo a large prime N.
For Proton, N is 2048 bits (256 bytes). The hash function used in SRP
must produce output of the same size as N to avoid bias when the hash
output is used as an exponent modulo N.

Standard SHA-512 produces only 512 bits (64 bytes). If we used SHA-512
directly, the SRP private key x would be at most 512 bits, and the
equation x mod N would effectively reduce the key space from 2048 bits
to 512 bits. An attacker could exploit this reduced space.

How it works
------------
PMHash concatenates four SHA-512 digests, each computed over the input
data with a different single-byte suffix:

    PMHash(data) = SHA-512(data || 0x00)
                || SHA-512(data || 0x01)
                || SHA-512(data || 0x02)
                || SHA-512(data || 0x03)

This produces 4 * 64 = 256 bytes = 2048 bits, matching the modulus size.

Each SHA-512 call processes slightly different input (the suffix byte
changes), so the four digests are independent. Concatenating them gives
a uniformly distributed 2048-bit output, assuming SHA-512 behaves as a
random oracle.

Security note
-------------
This construction is non-standard. A more conventional approach would be
to use a hash function with native 2048-bit output (like SHAKE-256 with
a 256-byte output length) or an approved KDF (like HKDF-Expand). Proton
chose this approach because it was simple to implement and predates the
widespread availability of extendable-output functions (XOFs) in crypto
libraries.

The construction is sound for its purpose (producing an unbiased SRP
exponent), but it should not be used as a general-purpose hash function.

Source: reverse-engineered from ProtonMail/proton-python-client
"""

import hashlib


def pmhash(data: bytes) -> bytes:
    """
    Compute Proton's 2048-bit hash.

    Args:
        data: Input bytes to hash.

    Returns:
        256 bytes (2048 bits) of hash output.

    Example:
        >>> len(pmhash(b"hello"))
        256
        >>> pmhash(b"hello") != pmhash(b"world")
        True
    """
    return b"".join(
        hashlib.sha512(data + bytes([i])).digest() for i in range(4)
    )
