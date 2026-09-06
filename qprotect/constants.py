"""Algorithm and compliance constants.

These identifiers deliberately mirror the CNSA 2.0 algorithm selections:
ML-KEM-1024, ML-DSA-87, AES-256-GCM, SHA-384/SHA-512, and HKDF-SHA-384.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


VERSION = 1
PACKAGE_VERSION = "0.2.0"


class KEM(StrEnum):
    ML_KEM_1024 = "ML-KEM-1024"


class Signature(StrEnum):
    ML_DSA_87 = "ML-DSA-87"


class AEAD(StrEnum):
    AES_256_GCM = "AES-256-GCM"


class Hash(StrEnum):
    SHA384 = "SHA-384"
    SHA512 = "SHA-512"


class KDF(StrEnum):
    HKDF_SHA384 = "HKDF-SHA-384"


class PBKDF(StrEnum):
    ARGON2ID = "argon2id"


class DiskCipher(StrEnum):
    AES_XTS_PLAIN64 = "aes-xts-plain64"


@dataclass(frozen=True)
class AlgorithmSuite:
    """Algorithm choices used by this toolkit."""

    kem: KEM = KEM.ML_KEM_1024
    signature: Signature = Signature.ML_DSA_87
    aead: AEAD = AEAD.AES_256_GCM
    kdf: KDF = KDF.HKDF_SHA384
    digest: Hash = Hash.SHA384
    disk_digest: Hash = Hash.SHA512
    disk_pbkdf: PBKDF = PBKDF.ARGON2ID
    disk_cipher: DiskCipher = DiskCipher.AES_XTS_PLAIN64
    disk_key_bits: int = 512


@dataclass(frozen=True)
class ComplianceProfile:
    """Non-secret description of the algorithm and validation posture."""

    suite: AlgorithmSuite
    algorithm_profile: str = "CNSA 2.0 algorithm selection"
    validation_status: str = "Not FIPS 140-3 validated or NSA certified"
    validation_boundary: str = "Application, cryptographic dependencies, OS integration, and operational controls"
    self_test_required: bool = True


CNSA_2_0 = AlgorithmSuite()
DEFAULT_PROFILE = ComplianceProfile(suite=CNSA_2_0)
