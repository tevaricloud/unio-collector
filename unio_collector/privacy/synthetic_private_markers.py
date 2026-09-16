from __future__ import annotations  # noqa: D100


def synthetic_private_key_marker() -> str:
    """Return the synthetic PEM marker used by privacy leak-detection tests."""
    return "-----BEGIN " + "PRIVATE KEY-----"


def synthetic_openssh_private_key_marker() -> str:
    """Return the synthetic OpenSSH marker used by privacy metadata checks."""
    return "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
