"""
SRP-6a (Secure Remote Password) client for Proton.

What is SRP?
------------
SRP is a zero-knowledge password authentication protocol defined in
RFC 5054 and RFC 2945. It allows a client to prove knowledge of a
password to a server without ever sending the password (or a hash
of it) over the network.

Key properties:
- The server stores a "verifier" v = g^x mod N, not the password.
- Even if the server's database is stolen, the attacker cannot
  recover passwords from verifiers (discrete log problem).
- A passive eavesdropper learns nothing about the password.
- An active attacker (MITM) cannot replay or forge authentication.
- Both sides prove their identity (mutual authentication).

How SRP works (simplified)
--------------------------
Setup (registration):
    1. Client picks password, server sends salt s
    2. Client computes x = H(s, password) and v = g^x mod N
    3. Server stores (username, s, v)

Authentication:
    1. Client generates random a, computes A = g^a mod N, sends A
    2. Server generates random b, computes B = k*v + g^b mod N, sends B
    3. Both compute u = H(A, B)
    4. Client computes S = (B - k*g^x)^(a + u*x) mod N
    5. Server computes S = (A * v^u)^b mod N
    6. Both sides get the same S (shared secret)
    7. Client sends M1 = H(A, B, S) as proof
    8. Server verifies M1, sends M2 = H(A, M1, S)
    9. Client verifies M2 (mutual authentication complete)

The beauty: the password never leaves the client. The server never
sees x. The shared secret S is computed independently by both sides
and will match only if the client used the correct password.

Proton's SRP specifics
----------------------
- Modulus N: 2048-bit prime, PGP-signed by Proton
- Generator g: 2
- Hash function: PMHash (custom 2048-bit, see pmhash.py)
- Password KDF: bcrypt + PMHash (see password.py)
- Byte order: little-endian (unusual; most SRP uses big-endian)

References:
- RFC 5054: Using SRP for TLS Authentication
- RFC 2945: The SRP Authentication and Key Exchange System
- T. Wu, "The Secure Remote Password Protocol", NDSS 1998

Source: reverse-engineered from ProtonMail/proton-python-client
"""

import os

from .password import hash_password
from .pmhash import pmhash

# SRP modulus size in bytes (2048 bits)
SRP_LEN_BYTES = 256


def _bytes_to_int(b: bytes) -> int:
    """Convert little-endian bytes to integer."""
    return int.from_bytes(b, "little")


def _int_to_bytes(n: int, length: int) -> bytes:
    """Convert integer to little-endian bytes of fixed length."""
    return n.to_bytes(length, "little")


def _hash_int(*values: int) -> int:
    """Hash one or more integers using PMHash, return as integer.

    Each integer is serialized as SRP_LEN_BYTES little-endian bytes
    before hashing. This ensures consistent input size.
    """
    data = b"".join(_int_to_bytes(v, SRP_LEN_BYTES) for v in values)
    return _bytes_to_int(pmhash(data))


class SRPClient:
    """
    SRP-6a client implementing Proton's authentication protocol.

    Usage:
        srp = SRPClient(password, modulus_bytes)
        A = srp.get_ephemeral()          # send to server
        M1 = srp.process_challenge(salt, B)  # compute proof
        # send A and M1 to server, receive M2
        assert srp.verify_server(M2)     # mutual auth
    """

    def __init__(
        self,
        password: str,
        modulus_bytes: bytes,
    ) -> None:
        """
        Initialize the SRP client.

        Args:
            password: The user's plaintext password.
            modulus_bytes: The 256-byte modulus N from /auth/info.
        """
        self.password = password.encode("utf-8")

        # The large prime N defining the SRP group.
        # All arithmetic is done modulo N.
        self.N = _bytes_to_int(modulus_bytes)

        # Generator g = 2. This is a generator of the multiplicative
        # group modulo N, meaning every element of the group can be
        # expressed as g^k mod N for some k.
        self.g = 2

        # SRP multiplier k = H(g, N).
        # In SRP-6a, k is derived from g and N to prevent a
        # "two-for-one" guess attack on the verifier.
        self.k = self._compute_k()

        # Random ephemeral secret a (256 bits).
        # This is used once and discarded after authentication.
        self.a = _bytes_to_int(os.urandom(32))

        # Public ephemeral A = g^a mod N.
        # This is sent to the server.
        self.A = pow(self.g, self.a, self.N)

        # Session key and proofs (set during process_challenge)
        self.K: bytes | None = None
        self.M1: bytes | None = None
        self.expected_M2: bytes | None = None

    def _compute_k(self) -> int:
        """
        Compute the SRP-6a multiplier k = H(g, N).

        Proton serializes g in big-endian and N in reversed big-endian
        for this computation. This matches their Go/C implementations.
        """
        g_be = self.g.to_bytes(SRP_LEN_BYTES, "big")
        n_be = self.N.to_bytes(SRP_LEN_BYTES, "big")
        return _bytes_to_int(pmhash(g_be + n_be[::-1]))

    def get_ephemeral(self) -> bytes:
        """
        Return the client's public ephemeral A as little-endian bytes.

        Send this to the server as ClientEphemeral (base64-encoded).
        """
        return _int_to_bytes(self.A, SRP_LEN_BYTES)

    def process_challenge(
        self,
        salt: bytes,
        server_ephemeral: bytes,
    ) -> bytes | None:
        """
        Process the server's SRP challenge and compute the client proof.

        This is where the core SRP math happens:
        1. Compute u = H(A, B) (scrambling parameter)
        2. Compute x from the password (via bcrypt + PMHash)
        3. Compute the shared secret S
        4. Derive the proof M1

        Args:
            salt: The user's salt from /auth/info.
            server_ephemeral: The server's public ephemeral B.

        Returns:
            The client proof M1, or None if the challenge is invalid.
        """
        B = _bytes_to_int(server_ephemeral)  # noqa: N806

        # Safety check: B mod N must not be zero.
        # If B = 0, the server is either broken or malicious.
        # With B = 0, the shared secret S would always be 0
        # regardless of the password, breaking authentication.
        if (B % self.N) == 0:
            return None

        # u = H(A, B) is the "scrambling parameter".
        # It binds A and B together so that an attacker cannot
        # replay A from a previous session with a new B.
        u = _hash_int(self.A, B)
        if u == 0:
            return None

        # x = password_hash(password, salt, N)
        # This is the SRP private key derived from the password.
        # See password.py for the full derivation.
        x = _bytes_to_int(
            hash_password(
                self.password, salt, _int_to_bytes(self.N, SRP_LEN_BYTES)
            )
        )

        # v = g^x mod N (the password verifier)
        # The server stores v. We compute it here to cancel it out
        # of the equation below.
        v = pow(self.g, x, self.N)

        # S = (B - k*v)^(a + u*x) mod N
        #
        # Why this works:
        # Server computed B = k*v + g^b mod N
        # So B - k*v = g^b mod N
        # And (g^b)^(a + u*x) = g^(b*(a + u*x)) mod N
        #
        # Server computes (A * v^u)^b = (g^a * g^(x*u))^b
        #                             = g^(b*(a + u*x)) mod N
        #
        # Both sides get the same S, but only if x (and thus the
        # password) is correct on the client side.
        S = pow((B - self.k * v), (self.a + u * x), self.N)  # noqa: N806

        # K = S as bytes. This is the shared session key.
        self.K = _int_to_bytes(S, SRP_LEN_BYTES)

        # M1 = H(A || B || K) is the client proof.
        # Sending M1 proves to the server that we computed the
        # correct S (and thus know the password).
        self.M1 = pmhash(
            _int_to_bytes(self.A, SRP_LEN_BYTES)
            + _int_to_bytes(B, SRP_LEN_BYTES)
            + self.K
        )

        # M2 = H(A || M1 || K) is the expected server proof.
        # The server will send this back so we can verify that
        # the server also knows v (mutual authentication).
        self.expected_M2 = pmhash(
            _int_to_bytes(self.A, SRP_LEN_BYTES) + self.M1 + self.K
        )

        return self.M1

    def verify_server(self, server_proof: bytes) -> bool:
        """
        Verify the server's proof for mutual authentication.

        The server sends M2 = H(A || M1 || K). If it matches our
        expected value, the server proved it knows the verifier v
        (and thus the authentication is mutual).

        Args:
            server_proof: The ServerProof from /auth response.

        Returns:
            True if the server proof is valid.
        """
        if self.expected_M2 is None:
            return False
        return server_proof == self.expected_M2
