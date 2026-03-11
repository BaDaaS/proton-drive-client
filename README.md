# Proton Drive Client

Educational Python client for the Proton Drive API, demonstrating how Proton's
SRP (Secure Remote Password) authentication and PGP-based encryption work under
the hood.

Built by [BaDaaS](https://badaas.be), an Applied Mathematics and Cryptography
Lab from Belgium.

## Why

Proton Drive has no official public API documentation. The only way to
understand how it works is to reverse-engineer the open-source web client and
third-party implementations. This project documents that knowledge as readable,
well-commented Python code.

## What you will learn

- **PMHash** (`pmhash.py`): Proton's custom 2048-bit hash function built from
  four concatenated SHA-512 digests
- **Password hashing** (`password.py`): How Proton derives SRP keys using
  bcrypt with a custom salt encoding
- **SRP-6a** (`srp.py`): The full Secure Remote Password protocol as
  implemented by Proton, with step-by-step explanations of the math
- **API client** (`client.py`): HTTP communication with the undocumented Proton
  API, including the authentication handshake

## Requirements

- Python >= 3.13
- [uv](https://docs.astral.sh/uv/) package manager

## Setup

```bash
uv sync
```

## Usage

Authenticate and list Drive shares:

```bash
uv run python -m proton_drive_client \
    --username user@proton.me \
    --list-shares
```

List children of a folder:

```bash
uv run python -m proton_drive_client \
    --username user@proton.me \
    --list-folder SHARE_ID LINK_ID
```

Note: file and folder names are encrypted. The `--list-folder` output shows
encrypted metadata. Decrypting names requires the PGP node key (not yet
implemented).

## Development

```bash
make help          # Show all targets
make install       # Install dependencies
make format        # Format code
make lint          # Run linter
make typecheck     # Run mypy
make test          # Run tests
make check         # Run all checks
```

## Project structure

```
src/proton_drive_client/
    __init__.py     # Package overview
    __main__.py     # CLI entry point
    pmhash.py       # PMHash: 2048-bit hash (4x SHA-512)
    password.py     # bcrypt + PMHash password derivation
    srp.py          # SRP-6a protocol implementation
    client.py       # Proton API HTTP client
tests/
    test_pmhash.py
    test_password.py
    test_srp.py
```

## References

- [RFC 5054: Using SRP for TLS Authentication](https://datatracker.ietf.org/doc/html/rfc5054)
- [RFC 2945: The SRP Authentication and Key Exchange System](https://datatracker.ietf.org/doc/html/rfc2945)
- T. Wu, "The Secure Remote Password Protocol", NDSS 1998
- [An Analysis of the ProtonMail Cryptographic Architecture](https://eprint.iacr.org/2018/1121.pdf)
  (Nadim Kobeissi, IACR ePrint 2018/1121)
- [Securing Cloud Storage with OpenPGP: An Analysis of Proton Drive](https://ethz.ch/content/dam/ethz/special-interest/infk/inst-infsec/appliedcrypto/education/theses/lea-micheloud-master-thesis.pdf)
  (Lea Micheloud, ETH Zurich Master Thesis)
- [ProtonMail/proton-python-client](https://github.com/ProtonMail/proton-python-client):
  official Python SRP library
- [henrybear327/Proton-API-Bridge](https://github.com/henrybear327/Proton-API-Bridge):
  Go bridge used by rclone
- [rclone protondrive backend](https://rclone.org/protondrive/)

## License

MIT
