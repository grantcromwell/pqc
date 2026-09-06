"""Atomic, restrictive file output helpers."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile

from .exceptions import QProtectError


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(
    path: str | Path,
    data: bytes,
    *,
    mode: int = 0o600,
    overwrite: bool = False,
) -> None:
    """Write a file without following the destination or exposing partial data."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    committed = False
    try:
        os.fchmod(fd, mode)
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            written = os.write(fd, view[offset:])
            if written <= 0:
                raise QProtectError(f"unable to write output: {destination}")
            offset += written
        os.fsync(fd)
        os.close(fd)
        fd = -1

        if overwrite:
            os.replace(temporary, destination)
        else:
            try:
                os.link(temporary, destination, follow_symlinks=False)
            except FileExistsError as exc:
                raise QProtectError(f"output already exists (use --force): {destination}") from exc
            temporary.unlink()
        committed = True
        _fsync_directory(destination.parent)
    except QProtectError:
        raise
    except OSError as exc:
        raise QProtectError(f"unable to commit output: {destination}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if not committed:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

