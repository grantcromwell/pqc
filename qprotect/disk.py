"""Safe LUKS2 whole-disk planning and command execution."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import re

from .constants import AlgorithmSuite
from .exceptions import DiskSafetyError

CONFIRM_FORMAT = "FORMAT"
_VALIDATED_PLAN = object()


@dataclass(frozen=True)
class LUKS2Plan:
    device: Path
    mapper_name: str
    key_file: Path | None = None
    header_file: Path | None = None
    iter_time_ms: int = 5000
    argon2_memory_kib: int | None = None
    argon2_parallelism: int | None = None
    sector_size: int = 4096
    integrity: str | None = None
    device_number: tuple[int, int] | None = field(default=None, repr=False)
    _validation_token: object | None = field(default=None, repr=False, compare=False)

    def format_args(self) -> list[str]:
        args = [
            "cryptsetup",
            "luksFormat",
            "--type",
            "luks2",
            "--batch-mode",
            "--cipher",
            "aes-xts-plain64",
            "--key-size",
            "512",
            "--hash",
            "sha512",
            "--pbkdf",
            "argon2id",
            "--iter-time",
            str(self.iter_time_ms),
            "--sector-size",
            str(self.sector_size),
            "--use-random",
        ]
        if self.argon2_memory_kib is not None:
            args.extend(["--pbkdf-memory", str(self.argon2_memory_kib)])
        if self.argon2_parallelism is not None:
            args.extend(["--pbkdf-parallel", str(self.argon2_parallelism)])
        if self.header_file is not None:
            args.extend(["--header", str(self.header_file)])
        if self.integrity:
            args.extend(["--integrity", self.integrity])
        args.append(str(self.device))
        if self.key_file is not None:
            args.append(str(self.key_file))
        return args

    def open_args(self) -> list[str]:
        args = [
            "cryptsetup",
            "open",
            "--type",
            "luks2",
            "--batch-mode",
        ]
        if self.header_file is not None:
            args.extend(["--header", str(self.header_file)])
        args.extend([str(self.device), self.mapper_name])
        if self.key_file is not None:
            args.extend(["--key-file", str(self.key_file)])
        return args

    def close_args(self) -> list[str]:
        return ["cryptsetup", "close", self.mapper_name]

    def backup_header_args(self, backup_path: str | Path) -> list[str]:
        args = ["cryptsetup", "luksHeaderBackup", str(self.device)]
        if self.header_file is not None:
            args.extend(["--header", str(self.header_file)])
        args.extend(["--header-backup-file", str(backup_path)])
        return args


@dataclass(frozen=True)
class DiskOperationResult:
    commands: tuple[list[str], ...]
    executed: bool
    outputs: tuple[str, ...] = ()


def _validate_mapper_name(name: str) -> None:
    if not isinstance(name, str) or not name or len(name) > 64:
        raise DiskSafetyError("mapper name must be 1..64 characters")
    if any(char.isalnum() is False and char not in "-_." for char in name):
        raise DiskSafetyError("mapper name may contain only letters, digits, '.', '-', and '_'")


def _validate_block_device(device: Path) -> tuple[Path, tuple[int, int]]:
    if not device.is_absolute():
        raise DiskSafetyError("device must be an absolute path")
    resolved = device.resolve()
    if not str(resolved).startswith("/dev/"):
        raise DiskSafetyError("resolved device must be under /dev")
    try:
        status = resolved.stat()
    except OSError as exc:
        raise DiskSafetyError("device is not accessible") from exc
    if not stat.S_ISBLK(status.st_mode):
        raise DiskSafetyError("path is not a block device")
    if not os.access(resolved, os.W_OK):
        raise DiskSafetyError("device is not writable by this user")
    return resolved, (os.major(status.st_rdev), os.minor(status.st_rdev))


def _validate_plan(plan: LUKS2Plan) -> None:
    if plan._validation_token is not _VALIDATED_PLAN or plan.device_number is None:
        raise DiskSafetyError("operation requires a plan returned by build_luks2_plan")
    resolved, device_number = _validate_block_device(plan.device)
    if resolved != plan.device or device_number != plan.device_number:
        raise DiskSafetyError("block-device identity changed after planning")
    if plan.key_file is not None:
        _validate_key_file(plan.key_file)


def _walk_lsblk(nodes: list[dict[str, object]]) -> list[dict[str, object]]:
    flattened: list[dict[str, object]] = []
    for node in nodes:
        flattened.append(node)
        children = node.get("children", [])
        if isinstance(children, list):
            flattened.extend(_walk_lsblk([item for item in children if isinstance(item, dict)]))
    return flattened


def _validate_format_target_unused(plan: LUKS2Plan) -> None:
    proc = subprocess.run(
        ["lsblk", "--json", "--paths", "--output", "PATH,TYPE,MOUNTPOINTS", str(plan.device)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
    )
    if proc.returncode != 0:
        raise DiskSafetyError("unable to verify block-device mount and holder state")
    try:
        nodes = json.loads(proc.stdout).get("blockdevices", [])
        flattened = _walk_lsblk(nodes)
    except (AttributeError, TypeError, ValueError) as exc:
        raise DiskSafetyError("unable to parse block-device safety information") from exc
    if not flattened:
        raise DiskSafetyError("block device was not found during final safety check")
    for index, node in enumerate(flattened):
        mounts = node.get("mountpoints")
        if isinstance(mounts, list) and any(mount for mount in mounts):
            raise DiskSafetyError("refusing to format a mounted device or one with mounted children")
        if index > 0:
            raise DiskSafetyError("refusing to format a device with active child mappings")

    major, minor = plan.device_number or (-1, -1)
    holders = Path(f"/sys/dev/block/{major}:{minor}/holders")
    try:
        if holders.is_dir() and any(holders.iterdir()):
            raise DiskSafetyError("refusing to format a block device with active holders")
    except OSError as exc:
        raise DiskSafetyError("unable to inspect block-device holders") from exc
    if Path("/dev/mapper", plan.mapper_name).exists():
        raise DiskSafetyError("requested mapper name is already active")


def _validate_key_file(key_file: Path) -> None:
    if not key_file.is_file():
        raise DiskSafetyError("key file does not exist")
    mode = key_file.stat().st_mode
    if mode & 0o077:
        raise DiskSafetyError("key file permissions must be 0600 or stricter")
    if key_file.stat().st_size == 0:
        raise DiskSafetyError("key file is empty")
    if key_file.is_symlink():
        raise DiskSafetyError("key file must not be a symbolic link")


def _validate_cryptsetup() -> None:
    binary = shutil.which("cryptsetup")
    if not binary:
        raise DiskSafetyError("cryptsetup is not installed")


def build_luks2_plan(
    device: str | Path,
    *,
    mapper_name: str,
    key_file: str | Path | None = None,
    header_file: str | Path | None = None,
    iter_time_ms: int = 5000,
    argon2_memory_kib: int | None = None,
    argon2_parallelism: int | None = None,
    sector_size: int = 4096,
    integrity: str | None = None,
) -> LUKS2Plan:
    """Build a LUKS2 plan without touching storage."""
    _validate_cryptsetup()
    _validate_mapper_name(mapper_name)
    device_path, device_number = _validate_block_device(Path(device))
    if iter_time_ms < 1000 or iter_time_ms > 10000:
        raise DiskSafetyError("iter_time_ms must be between 1000 and 10000")
    if sector_size not in (512, 1024, 2048, 4096):
        raise DiskSafetyError("sector_size must be 512, 1024, 2048, or 4096")
    if integrity is not None and (
        not isinstance(integrity, str) or not re.fullmatch(r"[A-Za-z0-9:+_.-]{1,64}", integrity)
    ):
        raise DiskSafetyError("integrity must be a supported algorithm name")
    if argon2_memory_kib is not None and not 1 <= argon2_memory_kib <= 4 * 1024 * 1024:
        raise DiskSafetyError("argon2_memory_kib must be between 1 and 4194304")
    if argon2_parallelism is not None and not 1 <= argon2_parallelism <= 1024:
        raise DiskSafetyError("argon2_parallelism must be between 1 and 1024")
    if key_file is not None:
        _validate_key_file(Path(key_file))
    return LUKS2Plan(
        device=device_path,
        mapper_name=mapper_name,
        key_file=Path(key_file).resolve() if key_file is not None else None,
        header_file=Path(header_file).absolute() if header_file is not None else None,
        iter_time_ms=iter_time_ms,
        argon2_memory_kib=argon2_memory_kib,
        argon2_parallelism=argon2_parallelism,
        sector_size=sector_size,
        integrity=integrity,
        device_number=device_number,
        _validation_token=_VALIDATED_PLAN,
    )


def confirmation_for(plan: LUKS2Plan) -> str:
    """Bind destructive confirmation to the validated device and exact format command."""
    _validate_plan(plan)
    material = "\0".join([*plan.format_args(), *(str(item) for item in plan.device_number or ())])
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16].upper()
    return f"{CONFIRM_FORMAT}-{plan.device.name}-{digest}"


def command_strings(plan: LUKS2Plan, backup_path: str | Path | None = None) -> list[str]:
    """Return shell-quoted commands for operator review."""
    commands = [plan.format_args(), plan.open_args(), plan.close_args()]
    if backup_path is not None:
        commands.append(plan.backup_header_args(backup_path))
    return [" ".join(shlex.quote(part) for part in command) for command in commands]


def execute_luks2_format(
    plan: LUKS2Plan,
    *,
    confirmation: str,
    dry_run: bool = False,
) -> DiskOperationResult:
    """Execute a destructive LUKS2 format only after explicit confirmation."""
    args = plan.format_args()
    if dry_run:
        return DiskOperationResult(commands=(args,), executed=False)
    _validate_plan(plan)
    if confirmation != confirmation_for(plan):
        raise DiskSafetyError(
            "destructive operation refused; pass the exact confirmation string printed by `disk plan`"
        )
    _validate_format_target_unused(plan)
    capture = plan.key_file is not None
    proc = subprocess.run(
        args,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        check=False,
    )
    output = ((proc.stdout or b"") + (proc.stderr or b"")).decode("utf-8", "replace")
    if proc.returncode != 0:
        raise DiskSafetyError(f"cryptsetup failed: {output.strip()}")
    return DiskOperationResult(commands=(args,), executed=True, outputs=(output,))


def execute_luks2_open(plan: LUKS2Plan) -> DiskOperationResult:
    _validate_plan(plan)
    if Path("/dev/mapper", plan.mapper_name).exists():
        raise DiskSafetyError("requested mapper name is already active")
    args = plan.open_args()
    capture = plan.key_file is not None
    proc = subprocess.run(
        args,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        check=False,
    )
    output = ((proc.stdout or b"") + (proc.stderr or b"")).decode("utf-8", "replace")
    if proc.returncode != 0:
        raise DiskSafetyError(f"cryptsetup failed: {output.strip()}")
    return DiskOperationResult(commands=(args,), executed=True, outputs=(output,))


def execute_luks2_close(plan: LUKS2Plan) -> DiskOperationResult:
    if plan._validation_token is not _VALIDATED_PLAN:
        raise DiskSafetyError("operation requires a plan returned by build_luks2_plan")
    args = plan.close_args()
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    output = (proc.stdout + proc.stderr).decode("utf-8", "replace")
    if proc.returncode != 0:
        raise DiskSafetyError(f"cryptsetup failed: {output.strip()}")
    return DiskOperationResult(commands=(args,), executed=True, outputs=(output,))


def whole_disk_profile() -> dict[str, str | int]:
    """Return the non-secret whole-disk algorithm profile."""
    suite = AlgorithmSuite()
    return {
        "type": "LUKS2",
        "cipher": suite.disk_cipher.value,
        "key_bits": suite.disk_key_bits,
        "pbkdf": suite.disk_pbkdf.value,
        "keyslot_hash": suite.disk_digest.value,
        "rng": "Linux /dev/random-backed cryptsetup key generation",
    }
