"""Authenticated post-quantum KEM/AEAD envelope."""
from __future__ import annotations

from base64 import b64decode, b64encode
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any

from cryptography.exceptions import InvalidTag

from .constants import AlgorithmSuite, VERSION
from .exceptions import EnvelopeError, ProviderError
from .provider import OpenSSLProvider

# Empty strings are valid: a zero-length payload produces an empty
# ciphertext, and base64 of zero bytes is the empty string.
_B64 = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
_KEY_ID = re.compile(r"^[0-9a-f]{32}$")
_CREATED_AT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")

MAX_RECIPIENTS = 32
MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
MAX_ENVELOPE_BYTES = 96 * 1024 * 1024
ML_DSA_87_SIGNATURE_BYTES = 4627

_RECIPIENT_FIELDS = {"key_id", "kem_ciphertext", "wrap_iv", "wrapped_key", "wrap_tag"}
_ENVELOPE_FIELDS = {
    "version",
    "format",
    "context",
    "created_at",
    "suite",
    "payload_iv",
    "ciphertext",
    "tag",
    "recipients",
    "signer_key_id",
    "signature_algorithm",
    "signature",
}


def _b64(data: bytes) -> str:
    return b64encode(data).decode("ascii")


def _unb64(value: str, field: str) -> bytes:
    if not isinstance(value, str) or not _B64.fullmatch(value):
        raise EnvelopeError(f"invalid base64 field: {field}")
    try:
        return b64decode(value, validate=True)
    except Exception as exc:
        raise EnvelopeError(f"invalid base64 field: {field}") from exc


def _canonical(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _normalise_context(context: str) -> str:
    if not isinstance(context, str) or not context or len(context) > 128:
        raise EnvelopeError("context must be a non-empty string of at most 128 characters")
    if any(ord(ch) < 32 or ord(ch) > 126 for ch in context):
        raise EnvelopeError("context must contain printable ASCII characters only")
    return context


def _normalise_paths(value: str | Path | Sequence[str | Path] | Iterable[str | Path]) -> list[Path]:
    if isinstance(value, (str, Path)):
        paths: list[Path] = [Path(value)]
    elif isinstance(value, Iterable):
        paths = [Path(item) for item in value]
    else:
        raise EnvelopeError("recipient key must be a path or sequence of paths")
    if not paths:
        raise EnvelopeError("at least one recipient key is required")
    if any(not path.is_file() for path in paths):
        raise EnvelopeError("all recipient public key files must exist")
    return paths


def _validate_key_id(key_id: str, field: str = "key_id") -> None:
    if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
        raise EnvelopeError(f"invalid {field}")


def _suite_dict(suite: AlgorithmSuite) -> dict[str, str]:
    return {
        "kem": suite.kem.value,
        "signature": suite.signature.value,
        "aead": suite.aead.value,
        "kdf": suite.kdf.value,
        "digest": suite.digest.value,
    }


@dataclass(frozen=True)
class WrappedRecipient:
    key_id: str
    kem_ciphertext: bytes
    wrap_iv: bytes
    wrapped_key: bytes
    wrap_tag: bytes

    def to_dict(self) -> dict[str, str]:
        return {
            "key_id": self.key_id,
            "kem_ciphertext": _b64(self.kem_ciphertext),
            "wrap_iv": _b64(self.wrap_iv),
            "wrapped_key": _b64(self.wrapped_key),
            "wrap_tag": _b64(self.wrap_tag),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WrappedRecipient:
        if not isinstance(data, dict) or set(data) != _RECIPIENT_FIELDS:
            raise EnvelopeError("recipient fields do not match the envelope specification")
        try:
            key_id = data["key_id"]
            _validate_key_id(key_id)
            kem_ciphertext = _unb64(data["kem_ciphertext"], "kem_ciphertext")
            wrap_iv = _unb64(data["wrap_iv"], "wrap_iv")
            wrapped_key = _unb64(data["wrapped_key"], "wrapped_key")
            wrap_tag = _unb64(data["wrap_tag"], "wrap_tag")
        except KeyError as exc:
            raise EnvelopeError(f"missing recipient field: {exc.args[0]}") from exc
        if len(kem_ciphertext) != 1568:
            raise EnvelopeError("invalid ML-KEM-1024 ciphertext length")
        if len(wrap_iv) != 12 or len(wrapped_key) != 32 or len(wrap_tag) != 16:
            raise EnvelopeError("invalid recipient wrapping parameters")
        return cls(
            key_id=key_id,
            kem_ciphertext=kem_ciphertext,
            wrap_iv=wrap_iv,
            wrapped_key=wrapped_key,
            wrap_tag=wrap_tag,
        )


@dataclass(frozen=True)
class Envelope:
    version: int
    context: str
    created_at: str
    suite: AlgorithmSuite
    payload_iv: bytes
    ciphertext: bytes
    tag: bytes
    recipients: tuple[WrappedRecipient, ...]
    signer_key_id: str | None
    signature: bytes | None

    def to_dict(self, *, include_signature: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "version": self.version,
            "format": "qprotect-envelope-v1",
            "context": self.context,
            "created_at": self.created_at,
            "suite": _suite_dict(self.suite),
            "payload_iv": _b64(self.payload_iv),
            "ciphertext": _b64(self.ciphertext),
            "tag": _b64(self.tag),
            "recipients": [recipient.to_dict() for recipient in self.recipients],
            "signer_key_id": self.signer_key_id,
            "signature_algorithm": self.suite.signature.value
            if (self.signer_key_id is not None or self.signature is not None)
            else None,
        }
        if include_signature and self.signature is not None:
            result["signature"] = _b64(self.signature)
        return result

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True, ensure_ascii=False)

    def unsigned_dict(self) -> dict[str, Any]:
        return self.to_dict(include_signature=False)

    def signature_material(self) -> bytes:
        return _canonical(self.unsigned_dict())

    def payload_aad(self) -> bytes:
        # AES-GCM AAD cannot include the payload ciphertext/tag it is about to
        # authenticate.  The ML-DSA signature still covers those fields.
        header = self.unsigned_dict()
        header.pop("ciphertext", None)
        header.pop("tag", None)
        return _canonical(header)

    def with_signature(self, signer_key_id: str, signature: bytes) -> Envelope:
        return replace(self, signer_key_id=signer_key_id, signature=signature)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Envelope:
        if not isinstance(data, dict) or not set(data).issubset(_ENVELOPE_FIELDS):
            raise EnvelopeError("envelope contains unknown fields")
        required = _ENVELOPE_FIELDS - {"signature"}
        if not required.issubset(data):
            missing = sorted(required - set(data))[0]
            raise EnvelopeError(f"missing envelope field: {missing}")
        try:
            version = data["version"]
            fmt = data["format"]
            context = _normalise_context(data["context"])
            created_at = data["created_at"]
            suite_data = data["suite"]
            payload_iv = _unb64(data["payload_iv"], "payload_iv")
            ciphertext = _unb64(data["ciphertext"], "ciphertext")
            tag = _unb64(data["tag"], "tag")
            recipients_raw = data["recipients"]
            signer_key_id = data.get("signer_key_id")
            signature = _unb64(data["signature"], "signature") if data.get("signature") is not None else None
        except KeyError as exc:
            raise EnvelopeError(f"missing envelope field: {exc.args[0]}") from exc
        if version != VERSION or fmt != "qprotect-envelope-v1":
            raise EnvelopeError("unsupported envelope version or format")
        if not isinstance(created_at, str) or not _CREATED_AT.fullmatch(created_at):
            raise EnvelopeError("invalid created_at")
        try:
            datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise EnvelopeError("invalid created_at") from exc
        expected = AlgorithmSuite()
        if suite_data != _suite_dict(expected):
            raise EnvelopeError("algorithm suite does not match CNSA 2.0 target")
        if not isinstance(recipients_raw, list) or not 1 <= len(recipients_raw) <= MAX_RECIPIENTS:
            raise EnvelopeError(f"envelope must have 1..{MAX_RECIPIENTS} recipients")
        recipients = tuple(WrappedRecipient.from_dict(item) for item in recipients_raw)
        if signer_key_id is not None:
            _validate_key_id(signer_key_id, "signer_key_id")
        if len(payload_iv) != 12 or len(tag) != 16:
            raise EnvelopeError("invalid payload AEAD parameters")
        if len(ciphertext) > MAX_PAYLOAD_BYTES:
            raise EnvelopeError("envelope payload exceeds the format limit")
        key_ids = [recipient.key_id for recipient in recipients]
        if len(key_ids) != len(set(key_ids)):
            raise EnvelopeError("duplicate recipient key_id")
        signature_algorithm = data.get("signature_algorithm")
        if signature is not None and signature_algorithm != expected.signature.value:
            raise EnvelopeError("invalid signature algorithm")
        if signature is None and signature_algorithm is not None:
            raise EnvelopeError("signature metadata without a signature")
        if signature is not None and signer_key_id is None:
            raise EnvelopeError("signed envelope missing signer_key_id")
        if signature is not None and len(signature) != ML_DSA_87_SIGNATURE_BYTES:
            raise EnvelopeError("invalid ML-DSA-87 signature length")
        return cls(
            version=version,
            context=context,
            created_at=created_at,
            suite=expected,
            payload_iv=payload_iv,
            ciphertext=ciphertext,
            tag=tag,
            recipients=recipients,
            signer_key_id=signer_key_id,
            signature=signature,
        )

    @classmethod
    def from_json(cls, value: str | bytes | Path) -> Envelope:
        if isinstance(value, Path):
            raw = value.read_bytes()
        elif isinstance(value, bytes):
            raw = value
        else:
            raw = value.encode("utf-8")
        if len(raw) > MAX_ENVELOPE_BYTES:
            raise EnvelopeError("envelope document exceeds the format limit")

        def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, item in pairs:
                if key in result:
                    raise EnvelopeError(f"duplicate JSON object key: {key}")
                result[key] = item
            return result

        def reject_constant(value: str) -> None:
            raise ValueError(f"non-finite JSON number: {value}")

        try:
            data = json.loads(
                raw,
                object_pairs_hook=reject_duplicates,
                parse_constant=reject_constant,
            )
        except EnvelopeError:
            raise
        except Exception as exc:
            raise EnvelopeError("envelope is not valid JSON") from exc
        if not isinstance(data, dict):
            raise EnvelopeError("envelope must be a JSON object")
        return cls.from_dict(data)


def _wrap_info(context: str, key_id: str) -> bytes:
    return f"qprotect/v1/wrap/{context}/{key_id}".encode("ascii")


def _zero(values: Iterable[bytearray]) -> None:
    for value in values:
        if isinstance(value, bytearray):
            for index in range(len(value)):
                value[index] = 0


def encrypt_envelope(
    plaintext: bytes,
    *,
    recipient_public_keys: str | Path | Sequence[str | Path],
    context: str,
    signer_private_key: str | Path | None = None,
    provider: OpenSSLProvider | None = None,
) -> Envelope:
    """Encrypt plaintext into an authenticated post-quantum KEM/AEAD envelope."""
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    if len(plaintext) > MAX_PAYLOAD_BYTES:
        raise EnvelopeError("payload exceeds the 64 MiB envelope-v1 limit")
    provider = provider or OpenSSLProvider()
    provider.assert_ready()
    context = _normalise_context(context)
    recipient_paths = _normalise_paths(recipient_public_keys)

    content_key = bytearray(provider.random_bytes(32))
    recipients: list[WrappedRecipient] = []
    recipient_ids: set[str] = set()
    shared: list[bytearray] = []
    try:
        for public_path in recipient_paths:
            key_id = provider.key_id(public_path)
            if key_id in recipient_ids:
                raise EnvelopeError("duplicate recipient public key")
            if len(recipient_ids) >= MAX_RECIPIENTS:
                raise EnvelopeError(f"at most {MAX_RECIPIENTS} recipients are supported")
            recipient_ids.add(key_id)
            kem_ciphertext, secret = provider.encapsulate_ml_kem_1024(public_path)
            secret_array = bytearray(secret)
            shared.append(secret_array)
            wrapping_key = provider.derive_key(
                bytes(secret_array),
                salt=kem_ciphertext,
                info=_wrap_info(context, key_id),
                length=32,
            )
            wrapping_iv = provider.random_bytes(12)
            wrapped_key, wrap_tag = provider.aead_encrypt(
                wrapping_key,
                wrapping_iv,
                bytes(content_key),
                _wrap_info(context, key_id),
            )
            recipients.append(
                WrappedRecipient(
                    key_id=key_id,
                    kem_ciphertext=kem_ciphertext,
                    wrap_iv=wrapping_iv,
                    wrapped_key=wrapped_key,
                    wrap_tag=wrap_tag,
                )
            )

        payload_iv = provider.random_bytes(12)
        created_at = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        signer_key_id = (
            provider.private_key_id(signer_private_key) if signer_private_key is not None else None
        )
        unsigned = Envelope(
            version=VERSION,
            context=context,
            created_at=created_at,
            suite=AlgorithmSuite(),
            payload_iv=payload_iv,
            ciphertext=b"",
            tag=b"",
            recipients=tuple(recipients),
            signer_key_id=signer_key_id,
            signature=None,
        )
        header = unsigned.to_dict(include_signature=False)
        header.pop("ciphertext", None)
        header.pop("tag", None)
        ciphertext, tag = provider.aead_encrypt(
            bytes(content_key),
            payload_iv,
            plaintext,
            _canonical(header),
        )
        envelope = Envelope(
            version=VERSION,
            context=context,
            created_at=created_at,
            suite=AlgorithmSuite(),
            payload_iv=payload_iv,
            ciphertext=ciphertext,
            tag=tag,
            recipients=tuple(recipients),
            signer_key_id=signer_key_id,
            signature=None,
        )
        if signer_private_key is not None:
            signature = provider.sign_ml_dsa_87(signer_private_key, envelope.signature_material())
            envelope = envelope.with_signature(signer_key_id, signature)
        return envelope
    except InvalidTag as exc:
        raise EnvelopeError("AES-GCM authentication failed") from exc
    except (OSError, ProviderError) as exc:
        raise EnvelopeError(f"unable to encrypt envelope: {exc}") from exc
    finally:
        _zero([content_key, *shared])


def decrypt_envelope(
    envelope: Envelope,
    *,
    recipient_private_key: str | Path,
    signer_public_key: str | Path | None = None,
    require_signature: bool | None = None,
    provider: OpenSSLProvider | None = None,
) -> bytes:
    """Decrypt and authenticate an envelope with one recipient private key."""
    provider = provider or OpenSSLProvider()
    provider.assert_ready()
    if envelope.version != VERSION:
        raise EnvelopeError("unsupported envelope version")
    if envelope.suite != AlgorithmSuite():
        raise EnvelopeError("unsupported algorithm suite")

    signature_required = signer_public_key is not None if require_signature is None else require_signature
    if signature_required and envelope.signature is None:
        raise EnvelopeError("sender signature is required")

    if envelope.signature is not None:
        if signer_public_key is None:
            raise EnvelopeError("signed envelope requires signer_public_key")
        expected_signer_id = provider.key_id(signer_public_key)
        if expected_signer_id != envelope.signer_key_id:
            raise EnvelopeError("signer public key does not match signer_key_id")
        if not provider.verify_ml_dsa_87(
            signer_public_key,
            envelope.signature_material(),
            envelope.signature,
        ):
            raise EnvelopeError("ML-DSA-87 signature verification failed")

    private_key_id = provider.private_key_id(recipient_private_key)
    recipient = next(
        (item for item in envelope.recipients if item.key_id == private_key_id),
        None,
    )
    if recipient is None:
        raise EnvelopeError("recipient private key does not match any envelope recipient")

    shared = bytearray()
    content_key = bytearray()
    try:
        secret = provider.decapsulate_ml_kem_1024(recipient_private_key, recipient.kem_ciphertext)
        shared = bytearray(secret)
        wrapping_key = provider.derive_key(
            bytes(shared),
            salt=recipient.kem_ciphertext,
            info=_wrap_info(envelope.context, recipient.key_id),
            length=32,
        )
        recovered = provider.aead_decrypt(
            wrapping_key,
            recipient.wrap_iv,
            recipient.wrapped_key,
            recipient.wrap_tag,
            _wrap_info(envelope.context, recipient.key_id),
        )
        content_key = bytearray(recovered)
        return provider.aead_decrypt(
            bytes(content_key),
            envelope.payload_iv,
            envelope.ciphertext,
            envelope.tag,
            envelope.payload_aad(),
        )
    except InvalidTag as exc:
        raise EnvelopeError("AES-GCM authentication failed") from exc
    except (OSError, ProviderError) as exc:
        raise EnvelopeError(f"unable to decrypt envelope: {exc}") from exc
    finally:
        _zero([shared, content_key])
