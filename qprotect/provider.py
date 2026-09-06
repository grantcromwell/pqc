"""OpenSSL-backed post-quantum primitive provider.

The CLI intentionally delegates ML-KEM and ML-DSA to OpenSSL so this project can
use the host's algorithm implementation rather than shipping an unaudited PQ
implementation.  A deployment that needs FIPS 140-3 validation must build this
against the same validated OpenSSL build/provider and keep the boundary audited.
"""
from __future__ import annotations

from dataclasses import dataclass
import hmac
import os
import re
from pathlib import Path
import subprocess
import tempfile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .constants import AEAD, Hash, KDF, KEM, Signature
from .exceptions import ProviderError
from .io_utils import atomic_write


@dataclass(frozen=True)
class ProviderInfo:
    """Non-secret provider capability report."""

    openssl_version: str
    ml_kem_1024: bool
    ml_dsa_87: bool
    algorithm_self_tests_passed: bool
    provider_names: tuple[str, ...]


class OpenSSLProvider:
    """Thin, auditable wrapper around OpenSSL's post-quantum CLI."""

    def __init__(self, binary: str | Path | None = None):
        self.binary = str(binary or os.environ.get("QPROTECT_OPENSSL", "openssl"))
        self._self_tests_passed = False
        self._validate_binary()

    def _run(
        self,
        args: list[str | Path],
        *,
        data: bytes | None = None,
        check: bool = True,
        timeout: float = 60.0,
    ) -> subprocess.CompletedProcess[bytes]:
        cmd = [self.binary, *map(str, args)]
        try:
            proc = subprocess.run(
                cmd,
                input=data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=timeout,
            )
        except FileNotFoundError as exc:
            raise ProviderError(f"OpenSSL executable not found: {self.binary}") from exc
        except subprocess.TimeoutExpired as exc:
            raise ProviderError(f"OpenSSL timed out: {' '.join(cmd)}") from exc
        if check and proc.returncode != 0:
            detail = proc.stderr.decode("utf-8", "replace").strip()
            raise ProviderError(f"OpenSSL failed ({proc.returncode}): {detail or 'unknown error'}")
        return proc

    def _validate_binary(self) -> None:
        proc = self._run(["version"], check=False)
        if proc.returncode != 0:
            detail = proc.stderr.decode("utf-8", "replace").strip()
            raise ProviderError(f"Unable to execute OpenSSL: {detail}")
        raw = proc.stdout.decode("utf-8", "replace")
        match = re.search(r"OpenSSL\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", raw)
        if not match:
            raise ProviderError(f"Unrecognized OpenSSL version output: {raw.strip()}")
        version = match.group(1)
        try:
            numbers = tuple(int(part) for part in version.split(".")[:2])
        except ValueError as exc:
            raise ProviderError(f"Unrecognized OpenSSL version: {version}") from exc
        if len(numbers) < 2 or numbers < (3, 5):
            raise ProviderError("OpenSSL 3.5+ is required for FIPS 203/204 algorithms")

    def version(self) -> str:
        return self._run(["version"]).stdout.decode("utf-8", "replace").strip()

    def provider_names(self) -> tuple[str, ...]:
        proc = self._run(["list", "-providers"])
        text = proc.stdout.decode("utf-8", "replace")
        names: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("Providers:") or line.startswith("name:"):
                continue
            # provider listing has one provider name per line without a prefix
            if line and not line.startswith(("status:", "version:", "build info:")):
                names.append(line)
        return tuple(sorted(set(names)))

    def algorithm_lists(self) -> tuple[str, str]:
        kems = self._run(["list", "-kem-algorithms"]).stdout.decode("utf-8", "replace")
        sigs = self._run(["list", "-signature-algorithms"]).stdout.decode("utf-8", "replace")
        return kems, sigs

    def info(self) -> ProviderInfo:
        kems, sigs = self.algorithm_lists()
        return ProviderInfo(
            openssl_version=self.version(),
            ml_kem_1024="ML-KEM-1024" in kems,
            ml_dsa_87="ML-DSA-87" in sigs,
            algorithm_self_tests_passed=self._self_tests_passed,
            provider_names=self.provider_names(),
        )

    def assert_ready(self) -> None:
        if self._self_tests_passed:
            return
        kems, sigs = self.algorithm_lists()
        if KEM.ML_KEM_1024 not in kems:
            raise ProviderError("OpenSSL does not expose ML-KEM-1024")
        if Signature.ML_DSA_87 not in sigs:
            raise ProviderError("OpenSSL does not expose ML-DSA-87")
        self._run_algorithm_self_tests()
        self._self_tests_passed = True

    def _run_algorithm_self_tests(self) -> None:
        """Exercise every required algorithm without inferring compliance from a name."""
        if self.digest(b"abc", Hash.SHA384).hex() != (
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
            "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        ):
            raise ProviderError("SHA-384 known-answer self-test failed")
        if self.digest(b"abc", Hash.SHA512).hex() != (
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea2"
            "0a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd"
            "454d4423643ce80e2a9ac94fa54ca49f"
        ):
            raise ProviderError("SHA-512 known-answer self-test failed")

        derived = self.derive_key(b"secret", salt=b"salt", info=b"info", length=32)
        expected = bytes.fromhex("29c042775183ec5dbc2c085eb49502b15d9e8abe4a4c1ef98e8e0fb95ad5f6a9")
        if not hmac.compare_digest(derived, expected):
            raise ProviderError("HKDF-SHA-384 known-answer self-test failed")

        key = bytes(range(32))
        nonce = bytes(range(12))
        ciphertext, tag = self.aead_encrypt(key, nonce, b"qprotect", b"self-test")
        if self.aead_decrypt(key, nonce, ciphertext, tag, b"self-test") != b"qprotect":
            raise ProviderError("AES-256-GCM self-test failed")

        with tempfile.TemporaryDirectory(prefix="qprotect-algorithm-selftest-") as tmp:
            root = Path(tmp)
            kem_private, kem_public = root / "kem-private.pem", root / "kem-public.pem"
            sig_private, sig_public = root / "sig-private.pem", root / "sig-public.pem"
            self.generate_ml_kem_keypair(kem_private, kem_public)
            kem_ciphertext, shared = self.encapsulate_ml_kem_1024(kem_public)
            recovered = self.decapsulate_ml_kem_1024(kem_private, kem_ciphertext)
            if not hmac.compare_digest(shared, recovered):
                raise ProviderError("ML-KEM-1024 pairwise self-test failed")
            self.generate_ml_dsa_keypair(sig_private, sig_public)
            signature = self.sign_ml_dsa_87(sig_private, b"qprotect self-test")
            if len(signature) != 4627 or not self.verify_ml_dsa_87(
                sig_public, b"qprotect self-test", signature
            ):
                raise ProviderError("ML-DSA-87 pairwise self-test failed")

    def private_public_key_der(self, private_key_path: str | Path) -> bytes:
        return self._run(["pkey", "-in", private_key_path, "-pubout", "-outform", "DER"]).stdout

    def private_key_id(self, private_key_path: str | Path) -> str:
        der = self.private_public_key_der(private_key_path)
        return self.digest(der, Hash.SHA384).hex()[:32]

    def random_bytes(self, length: int) -> bytes:
        if length < 0:
            raise ValueError("length must be non-negative")
        if length == 0:
            return b""
        return self._run(["rand", str(length)]).stdout

    @staticmethod
    def digest(data: bytes, algorithm: Hash = Hash.SHA384) -> bytes:
        if algorithm == Hash.SHA384:
            chosen = hashes.SHA384()
        elif algorithm == Hash.SHA512:
            chosen = hashes.SHA512()
        else:
            raise ValueError("unsupported digest")
        digest = hashes.Hash(chosen)
        digest.update(data)
        return digest.finalize()

    @staticmethod
    def derive_key(
        secret: bytes,
        *,
        salt: bytes,
        info: bytes,
        length: int = 32,
        algorithm: KDF = KDF.HKDF_SHA384,
    ) -> bytes:
        if algorithm != KDF.HKDF_SHA384:
            raise ValueError("unsupported KDF")
        hkdf = HKDF(algorithm=hashes.SHA384(), length=length, salt=salt, info=info)
        return hkdf.derive(secret)

    @staticmethod
    def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
        if len(key) != 32 or len(nonce) != 12:
            raise ValueError("AES-256-GCM requires a 32-byte key and 12-byte nonce")
        combined = AESGCM(key).encrypt(nonce, plaintext, aad)
        return combined[:-16], combined[-16:]

    @staticmethod
    def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
        if len(key) != 32 or len(nonce) != 12 or len(tag) != 16:
            raise ValueError("invalid AES-256-GCM parameters")
        return AESGCM(key).decrypt(nonce, ciphertext + tag, aad)

    def public_key_der(self, public_key_path: str | Path) -> bytes:
        return self._run(["pkey", "-pubin", "-in", public_key_path, "-outform", "DER"]).stdout

    def key_id(self, public_key_path: str | Path) -> str:
        der = self.public_key_der(public_key_path)
        return self.digest(der, Hash.SHA384).hex()[:32]

    def _generate_keypair(
        self,
        algorithm: str,
        private_path: str | Path,
        public_path: str | Path,
        *,
        overwrite: bool,
    ) -> None:
        private_path = Path(private_path)
        public_path = Path(public_path)
        if private_path.resolve() == public_path.resolve():
            raise ProviderError("private and public key paths must be different")
        private_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        public_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.TemporaryDirectory(prefix="qprotect-keygen-") as tmp:
            root = Path(tmp)
            generated_private = root / "private.pem"
            generated_public = root / "public.pem"
            self._run(["genpkey", "-algorithm", algorithm, "-out", generated_private])
            os.chmod(generated_private, 0o600)
            self._run(["pkey", "-in", generated_private, "-pubout", "-out", generated_public])
            atomic_write(public_path, generated_public.read_bytes(), mode=0o644, overwrite=overwrite)
            atomic_write(private_path, generated_private.read_bytes(), mode=0o600, overwrite=overwrite)

    def generate_ml_kem_keypair(
        self, private_path: str | Path, public_path: str | Path, *, overwrite: bool = False
    ) -> None:
        self._generate_keypair(
            KEM.ML_KEM_1024, private_path, public_path, overwrite=overwrite
        )

    def generate_ml_dsa_keypair(
        self, private_path: str | Path, public_path: str | Path, *, overwrite: bool = False
    ) -> None:
        self._generate_keypair(
            Signature.ML_DSA_87, private_path, public_path, overwrite=overwrite
        )

    def encapsulate_ml_kem_1024(self, public_key_path: str | Path) -> tuple[bytes, bytes]:
        with tempfile.TemporaryDirectory(prefix="qprotect-kem-") as tmp:
            tmp_path = Path(tmp)
            ciphertext_path = tmp_path / "ciphertext.bin"
            secret_path = tmp_path / "secret.bin"
            self._run(
                [
                    "pkeyutl",
                    "-pubin",
                    "-inkey",
                    public_key_path,
                    "-encap",
                    "-out",
                    ciphertext_path,
                    "-secret",
                    secret_path,
                ]
            )
            return ciphertext_path.read_bytes(), secret_path.read_bytes()

    def decapsulate_ml_kem_1024(self, private_key_path: str | Path, ciphertext: bytes) -> bytes:
        with tempfile.TemporaryDirectory(prefix="qprotect-kem-") as tmp:
            tmp_path = Path(tmp)
            ciphertext_path = tmp_path / "ciphertext.bin"
            secret_path = tmp_path / "secret.bin"
            ciphertext_path.write_bytes(ciphertext)
            self._run(
                [
                    "pkeyutl",
                    "-inkey",
                    private_key_path,
                    "-decap",
                    "-in",
                    ciphertext_path,
                    "-secret",
                    secret_path,
                ]
            )
            return secret_path.read_bytes()

    def sign_ml_dsa_87(self, private_key_path: str | Path, data: bytes) -> bytes:
        with tempfile.TemporaryDirectory(prefix="qprotect-sign-") as tmp:
            tmp_path = Path(tmp)
            data_path = tmp_path / "data.bin"
            signature_path = tmp_path / "signature.bin"
            data_path.write_bytes(data)
            self._run(
                [
                    "pkeyutl",
                    "-sign",
                    "-rawin",
                    "-inkey",
                    private_key_path,
                    "-in",
                    data_path,
                    "-out",
                    signature_path,
                ]
            )
            return signature_path.read_bytes()

    def verify_ml_dsa_87(self, public_key_path: str | Path, data: bytes, signature: bytes) -> bool:
        with tempfile.TemporaryDirectory(prefix="qprotect-verify-") as tmp:
            tmp_path = Path(tmp)
            data_path = tmp_path / "data.bin"
            signature_path = tmp_path / "signature.bin"
            data_path.write_bytes(data)
            signature_path.write_bytes(signature)
            proc = self._run(
                [
                    "pkeyutl",
                    "-verify",
                    "-rawin",
                    "-pubin",
                    "-inkey",
                    public_key_path,
                    "-in",
                    data_path,
                    "-sigfile",
                    signature_path,
                ],
                check=False,
            )
            return proc.returncode == 0

    def zeroize(self, data: bytearray | list[bytearray]) -> None:
        for value in data if isinstance(data, list) else [data]:
            if isinstance(value, bytearray):
                for i in range(len(value)):
                    value[i] = 0
