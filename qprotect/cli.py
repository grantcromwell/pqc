"""Command-line interface for qprotect."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Sequence

from .constants import AlgorithmSuite, ComplianceProfile, DEFAULT_PROFILE, PACKAGE_VERSION, VERSION
from .disk import (
    build_luks2_plan,
    command_strings,
    confirmation_for,
    execute_luks2_close,
    execute_luks2_format,
    execute_luks2_open,
    whole_disk_profile,
)
from .envelope import MAX_ENVELOPE_BYTES, Envelope, decrypt_envelope, encrypt_envelope
from .exceptions import QProtectError
from .identity import IdentityRecord
from .io_utils import atomic_write
from .keys import generate_ml_dsa_keypair, generate_ml_kem_keypair
from .provider import OpenSSLProvider


def _provider(args: argparse.Namespace) -> OpenSSLProvider:
    return OpenSSLProvider(args.openssl)


def _write_private(path: Path, data: bytes, *, force: bool = False) -> None:
    atomic_write(path, data, mode=0o600, overwrite=force)


def _same_path(left: Path, right: Path) -> bool:
    try:
        return left.resolve() == right.resolve()
    except OSError:
        return left == right


def _read_input(path: Path, *, maximum: int = 64 * 1024 * 1024) -> bytes:
    if not path.is_file():
        raise QProtectError(f"input does not exist: {path}")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise QProtectError(f"unable to inspect input: {path}") from exc
    if size > maximum:
        raise QProtectError(f"input exceeds the {maximum // (1024 * 1024)} MiB format limit")
    data = path.read_bytes()
    if len(data) > maximum:
        raise QProtectError(f"input exceeds the {maximum // (1024 * 1024)} MiB format limit")
    return data


def _profile_json(profile: ComplianceProfile = DEFAULT_PROFILE) -> dict[str, object]:
    return {
        "version": VERSION,
        "suite": asdict(profile.suite),
        "algorithm_profile": profile.algorithm_profile,
        "validation_status": profile.validation_status,
        "validation_boundary": profile.validation_boundary,
        "self_test_required": profile.self_test_required,
    }


def _provider_json(provider: OpenSSLProvider) -> tuple[dict[str, object], bool]:
    try:
        provider.assert_ready()
        ready = True
    except QProtectError:
        ready = False
    return asdict(provider.info()), ready


def _doctor(args: argparse.Namespace) -> int:
    provider = OpenSSLProvider(args.openssl)
    provider_data, ready = _provider_json(provider)
    result = {
        "tool_version": PACKAGE_VERSION,
        "ready": ready,
        "profile": _profile_json(),
        "provider": provider_data,
        "whole_disk": whole_disk_profile(),
        "notes": [
            "Algorithm self-tests establish local capability, not FIPS 140-3 validation.",
            "qprotect does not infer compliance from an OpenSSL provider name.",
        ],
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if ready else 1


def _keygen(args: argparse.Namespace) -> int:
    provider = _provider(args)
    private = Path(args.private)
    public = Path(args.public)
    if (private.exists() or public.exists()) and not args.force:
        raise QProtectError("key output exists (use --force)")
    if args.type == "kem":
        key_id = generate_ml_kem_keypair(private, public, provider, overwrite=args.force)
    else:
        key_id = generate_ml_dsa_keypair(private, public, provider, overwrite=args.force)
    print(key_id)
    return 0


def _encrypt_file(args: argparse.Namespace) -> int:
    provider = _provider(args)
    input_path = Path(args.input)
    output_path = Path(args.output)
    if _same_path(input_path, output_path):
        raise QProtectError("input and output must be different paths")
    plaintext = _read_input(input_path)
    envelope = encrypt_envelope(
        plaintext,
        recipient_public_keys=args.recipient,
        context=args.context,
        signer_private_key=args.signer,
        provider=provider,
    )
    _write_private(output_path, envelope.to_json(indent=2).encode("utf-8"), force=args.force)
    print(f"encrypted {len(plaintext)} bytes to {output_path}")
    return 0


def _decrypt_file(args: argparse.Namespace) -> int:
    provider = _provider(args)
    input_path = Path(args.input)
    output_path = Path(args.output)
    if _same_path(input_path, output_path):
        raise QProtectError("input and output must be different paths")
    envelope = Envelope.from_json(_read_input(input_path, maximum=MAX_ENVELOPE_BYTES))
    plaintext = decrypt_envelope(
        envelope,
        recipient_private_key=args.recipient_private,
        signer_public_key=args.signer_public,
        provider=provider,
    )
    _write_private(output_path, plaintext, force=args.force)
    print(f"decrypted {len(plaintext)} bytes to {output_path}")
    return 0


def _encrypt_identity(args: argparse.Namespace) -> int:
    provider = _provider(args)
    input_path = Path(args.input)
    output_path = Path(args.output)
    if _same_path(input_path, output_path):
        raise QProtectError("input and output must be different paths")
    record = IdentityRecord.from_json(_read_input(input_path, maximum=1024 * 1024))
    envelope = encrypt_envelope(
        record.to_payload(),
        recipient_public_keys=args.recipient,
        context="identity",
        signer_private_key=args.signer,
        provider=provider,
    )
    _write_private(output_path, envelope.to_json(indent=2).encode("utf-8"), force=args.force)
    print(f"identity record encrypted to {output_path}")
    return 0


def _decrypt_identity(args: argparse.Namespace) -> int:
    provider = _provider(args)
    input_path = Path(args.input)
    output_path = Path(args.output)
    if _same_path(input_path, output_path):
        raise QProtectError("input and output must be different paths")
    envelope = Envelope.from_json(_read_input(input_path, maximum=MAX_ENVELOPE_BYTES))
    plaintext = decrypt_envelope(
        envelope,
        recipient_private_key=args.recipient_private,
        signer_public_key=args.signer_public,
        provider=provider,
    )
    record = IdentityRecord.from_json(plaintext)
    rendered = json.dumps(record.to_dict(), indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
    _write_private(output_path, rendered, force=args.force)
    print(f"identity record decrypted to {output_path}")
    return 0


def _disk_plan(args: argparse.Namespace) -> int:
    plan = build_luks2_plan(
        args.device,
        mapper_name=args.mapper,
        key_file=args.key_file,
        header_file=args.header,
        iter_time_ms=args.iter_time,
        argon2_memory_kib=args.pbkdf_memory,
        argon2_parallelism=args.pbkdf_parallel,
        sector_size=args.sector_size,
        integrity=args.integrity,
    )
    result = {
        "profile": whole_disk_profile(),
        "confirmation": confirmation_for(plan),
        "commands": command_strings(plan, backup_path=args.header_backup),
        "danger": "luksFormat destroys all data on the target device",
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _disk_format(args: argparse.Namespace) -> int:
    plan = build_luks2_plan(
        args.device,
        mapper_name=args.mapper,
        key_file=args.key_file,
        header_file=args.header,
        iter_time_ms=args.iter_time,
        argon2_memory_kib=args.pbkdf_memory,
        argon2_parallelism=args.pbkdf_parallel,
        sector_size=args.sector_size,
        integrity=args.integrity,
    )
    if not args.execute:
        result = {
            "profile": whole_disk_profile(),
            "confirmation": confirmation_for(plan),
            "commands": command_strings(plan, backup_path=args.header_backup),
            "danger": "luksFormat destroys all data on the target device",
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    result = execute_luks2_format(plan, confirmation=args.confirmation, dry_run=False)
    print(json.dumps({"executed": True, "commands": result.commands}, indent=2))
    return 0


def _disk_open(args: argparse.Namespace) -> int:
    plan = build_luks2_plan(
        args.device,
        mapper_name=args.mapper,
        key_file=args.key_file,
        header_file=args.header,
        iter_time_ms=args.iter_time,
        argon2_memory_kib=args.pbkdf_memory,
        argon2_parallelism=args.pbkdf_parallel,
        sector_size=args.sector_size,
        integrity=args.integrity,
    )
    result = execute_luks2_open(plan)
    print(json.dumps({"opened": plan.mapper_name, "commands": result.commands}, indent=2))
    return 0


def _disk_close(args: argparse.Namespace) -> int:
    plan = build_luks2_plan(
        args.device,
        mapper_name=args.mapper,
        key_file=args.key_file,
        header_file=args.header,
        iter_time_ms=args.iter_time,
        argon2_memory_kib=args.pbkdf_memory,
        argon2_parallelism=args.pbkdf_parallel,
        sector_size=args.sector_size,
        integrity=args.integrity,
    )
    result = execute_luks2_close(plan)
    print(json.dumps({"closed": plan.mapper_name, "commands": result.commands}, indent=2))
    return 0


def _selftest(args: argparse.Namespace) -> int:
    provider = _provider(args)
    with tempfile.TemporaryDirectory(prefix="qprotect-selftest-") as tmp:
        root = Path(tmp)
        recipient_private = root / "recipient-private.pem"
        recipient_public = root / "recipient-public.pem"
        signer_private = root / "signer-private.pem"
        signer_public = root / "signer-public.pem"
        recipient_id = generate_ml_kem_keypair(recipient_private, recipient_public, provider)
        signer_id = generate_ml_dsa_keypair(signer_private, signer_public, provider)
        plaintext = b"qprotect self-test"
        envelope = encrypt_envelope(
            plaintext,
            recipient_public_keys=[recipient_public],
            context="selftest",
            signer_private_key=signer_private,
            provider=provider,
        )
        parsed = Envelope.from_json(envelope.to_json(indent=None))
        recovered = decrypt_envelope(
            parsed,
            recipient_private_key=recipient_private,
            signer_public_key=signer_public,
            provider=provider,
        )
        if recovered != plaintext:
            raise QProtectError("self-test round-trip mismatch")
        print(
            json.dumps(
                {
                    "ok": True,
                    "recipient_key_id": recipient_id,
                    "signer_key_id": signer_id,
                    "context": "selftest",
                },
                indent=2,
            )
        )
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qprotect",
        description="Post-quantum envelope protection and guarded LUKS2 planning",
    )
    parser.add_argument("--version", action="version", version=f"qprotect {PACKAGE_VERSION}")
    parser.add_argument("--openssl", default=os.environ.get("QPROTECT_OPENSSL", "openssl"))
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser("doctor", help="report algorithm and validation status")
    doctor.set_defaults(handler=_doctor)

    keygen = subparsers.add_parser("keygen", help="generate an ML-KEM-1024 or ML-DSA-87 keypair")
    keygen.add_argument("--type", choices=("kem", "sign"), required=True)
    keygen.add_argument("--private", type=Path, required=True)
    keygen.add_argument("--public", type=Path, required=True)
    keygen.add_argument("--force", action="store_true")
    keygen.set_defaults(handler=_keygen)

    encrypt = subparsers.add_parser("encrypt", help="encrypt an arbitrary file")
    encrypt.add_argument("--input", type=Path, required=True)
    encrypt.add_argument("--output", type=Path, required=True)
    encrypt.add_argument("--recipient", action="append", required=True, help="recipient ML-KEM public key (repeatable)")
    encrypt.add_argument("--signer", type=Path, help="optional ML-DSA-87 signing private key")
    encrypt.add_argument("--context", default="file")
    encrypt.add_argument("--force", action="store_true")
    encrypt.set_defaults(handler=_encrypt_file)

    decrypt = subparsers.add_parser("decrypt", help="decrypt an arbitrary envelope")
    decrypt.add_argument("--input", type=Path, required=True)
    decrypt.add_argument("--output", type=Path, required=True)
    decrypt.add_argument("--recipient-private", type=Path, required=True)
    decrypt.add_argument("--signer-public", type=Path)
    decrypt.add_argument("--force", action="store_true")
    decrypt.set_defaults(handler=_decrypt_file)

    identity_encrypt = subparsers.add_parser("identity-encrypt", help="validate and encrypt sensitive identity JSON")
    identity_encrypt.add_argument("--input", type=Path, required=True)
    identity_encrypt.add_argument("--output", type=Path, required=True)
    identity_encrypt.add_argument("--recipient", action="append", required=True)
    identity_encrypt.add_argument("--signer", type=Path)
    identity_encrypt.add_argument("--force", action="store_true")
    identity_encrypt.set_defaults(handler=_encrypt_identity)

    identity_decrypt = subparsers.add_parser("identity-decrypt", help="decrypt and validate sensitive identity JSON")
    identity_decrypt.add_argument("--input", type=Path, required=True)
    identity_decrypt.add_argument("--output", type=Path, required=True)
    identity_decrypt.add_argument("--recipient-private", type=Path, required=True)
    identity_decrypt.add_argument("--signer-public", type=Path)
    identity_decrypt.add_argument("--force", action="store_true")
    identity_decrypt.set_defaults(handler=_decrypt_identity)

    disk = subparsers.add_parser("disk", help="plan or operate LUKS2 whole-disk encryption")
    disk_subparsers = disk.add_subparsers(dest="disk_command", required=True)
    disk_plan_parser = disk_subparsers.add_parser("plan", help="print exact cryptsetup commands")
    disk_format_parser = disk_subparsers.add_parser("format", help="plan or execute destructive LUKS2 formatting")
    disk_open_parser = disk_subparsers.add_parser("open", help="open a LUKS2 device")
    disk_close_parser = disk_subparsers.add_parser("close", help="close a LUKS2 device")

    for disk_parser in (disk_plan_parser, disk_format_parser, disk_open_parser, disk_close_parser):
        disk_parser.add_argument("--device", type=Path, required=True)
        disk_parser.add_argument("--mapper", required=True)
        disk_parser.add_argument("--key-file", type=Path)
        disk_parser.add_argument("--header", type=Path)
        disk_parser.add_argument("--iter-time", type=int, default=5000)
        disk_parser.add_argument("--pbkdf-memory", type=int)
        disk_parser.add_argument("--pbkdf-parallel", type=int)
        disk_parser.add_argument("--sector-size", type=int, default=4096)
        disk_parser.add_argument("--integrity")
        disk_parser.add_argument("--header-backup", type=Path)
    disk_plan_parser.set_defaults(handler=_disk_plan)
    disk_format_parser.add_argument("--execute", action="store_true")
    disk_format_parser.add_argument("--confirmation", default="")
    disk_format_parser.set_defaults(handler=_disk_format)
    disk_open_parser.set_defaults(handler=_disk_open)
    disk_close_parser.set_defaults(handler=_disk_close)

    selftest = subparsers.add_parser("selftest", help="run a full signed KEM/AEAD round-trip")
    selftest.set_defaults(handler=_selftest)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except QProtectError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130
