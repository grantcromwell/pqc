"""Key generation and fingerprint helpers."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .provider import OpenSSLProvider


def generate_ml_kem_keypair(
    private_path: str | Path,
    public_path: str | Path,
    provider: OpenSSLProvider,
    *,
    overwrite: bool = False,
) -> str:
    """Generate an ML-KEM-1024 keypair and return the recipient key ID."""
    provider.assert_ready()
    provider.generate_ml_kem_keypair(private_path, public_path, overwrite=overwrite)
    return provider.key_id(public_path)


def generate_ml_dsa_keypair(
    private_path: str | Path,
    public_path: str | Path,
    provider: OpenSSLProvider,
    *,
    overwrite: bool = False,
) -> str:
    """Generate an ML-DSA-87 signing keypair and return the signer key ID."""
    provider.assert_ready()
    provider.generate_ml_dsa_keypair(private_path, public_path, overwrite=overwrite)
    return provider.key_id(public_path)
