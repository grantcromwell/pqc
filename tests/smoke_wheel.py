#!/usr/bin/env python3
"""Smoke test an installed wheel and its interoperability with the C++ CLI."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
CPP_TOOL = ROOT / "cpp" / "build" / "qprotect_cpp_tool"


def run(*args: object, cwd: Path, env: dict[str, str], success: bool = True) -> subprocess.CompletedProcess[str]:
    command = [str(arg) for arg in args]
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, check=False)
    if (result.returncode == 0) != success:
        raise AssertionError(
            f"unexpected exit {result.returncode} from {command!r}\n"
            f"stdout: {result.stdout[-500:]}\nstderr: {result.stderr[-500:]}"
        )
    return result


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python tests/smoke_wheel.py WHEEL_OR_WHEEL_DIRECTORY", file=sys.stderr)
        return 2
    wheel_argument = Path(sys.argv[1]).resolve()
    wheels = sorted(wheel_argument.glob("qprotect-*.whl")) if wheel_argument.is_dir() else [wheel_argument]
    if len(wheels) != 1 or not wheels[0].is_file():
        print("expected exactly one qprotect wheel", file=sys.stderr)
        return 2
    if not CPP_TOOL.is_file():
        print("build the C++ tool first with: make -C cpp", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="qprotect-wheel-smoke-") as temporary:
        work = Path(temporary)
        package = work / "package"
        run(
            sys.executable, "-m", "pip", "install", "--no-index", "--no-deps",
            "--target", package, wheels[0], cwd=work, env=os.environ.copy(),
        )
        env = os.environ.copy()
        env["PYTHONPATH"] = str(package)
        cli = package / "bin" / "qprotect"
        if not cli.is_file():
            raise AssertionError("wheel did not install the qprotect command")
        origin = run(
            sys.executable, "-c", "import qprotect; print(qprotect.__file__)",
            cwd=work, env=env,
        ).stdout.strip()
        if not Path(origin).resolve().is_relative_to(package.resolve()):
            raise AssertionError(f"loaded package outside wheel install: {origin}")

        doctor = json.loads(run(cli, "doctor", cwd=work, env=env).stdout)
        if not doctor["ready"] or not doctor["provider"]["algorithm_self_tests_passed"]:
            raise AssertionError("installed wheel failed algorithm readiness checks")

        kem_private, kem_public = work / "kem-private.pem", work / "kem-public.pem"
        sign_private, sign_public = work / "sign-private.pem", work / "sign-public.pem"
        run(cli, "keygen", "--type", "kem", "--private", kem_private, "--public", kem_public,
            cwd=work, env=env)
        run(cli, "keygen", "--type", "sign", "--private", sign_private, "--public", sign_public,
            cwd=work, env=env)

        plaintext = work / "plaintext.bin"
        plaintext.write_bytes(os.urandom(8192))
        python_envelope, cpp_envelope = work / "python.qpe", work / "cpp.qpe"
        cpp_output, python_output = work / "cpp-output.bin", work / "python-output.bin"
        run(cli, "encrypt", "--input", plaintext, "--output", python_envelope,
            "--recipient", kem_public, "--signer", sign_private, cwd=work, env=env)
        run(CPP_TOOL, "decrypt", "--input", python_envelope, "--output", cpp_output,
            "--recipient-private", kem_private, "--signer-public", sign_public,
            cwd=work, env=env)
        run(CPP_TOOL, "encrypt", "--input", plaintext, "--output", cpp_envelope,
            "--recipient", kem_public, "--signer", sign_private, cwd=work, env=env)
        run(cli, "decrypt", "--input", cpp_envelope, "--output", python_output,
            "--recipient-private", kem_private, "--signer-public", sign_public,
            cwd=work, env=env)
        original = plaintext.read_bytes()
        if cpp_output.read_bytes() != original or python_output.read_bytes() != original:
            raise AssertionError("cross-language payload mismatch")

        run(cli, "decrypt", "--input", cpp_envelope, "--output", python_output,
            "--recipient-private", kem_private, "--signer-public", sign_public,
            cwd=work, env=env, success=False)
        if python_output.read_bytes() != original:
            raise AssertionError("no-clobber failure changed an existing output")

        tampered = json.loads(cpp_envelope.read_text())
        ciphertext = bytearray(base64.b64decode(tampered["ciphertext"]))
        ciphertext[0] ^= 1
        tampered["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")
        tampered_path, rejected_output = work / "tampered.qpe", work / "rejected.bin"
        tampered_path.write_text(json.dumps(tampered))
        run(cli, "decrypt", "--input", tampered_path, "--output", rejected_output,
            "--recipient-private", kem_private, "--signer-public", sign_public,
            cwd=work, env=env, success=False)
        if rejected_output.exists():
            raise AssertionError("tampered envelope created a plaintext output")

        identity_envelope, identity_output = work / "identity.qpe", work / "identity.json"
        run(cli, "identity-encrypt", "--input", ROOT / "examples" / "identity.json",
            "--output", identity_envelope, "--recipient", kem_public, "--signer", sign_private,
            cwd=work, env=env)
        run(cli, "identity-decrypt", "--input", identity_envelope, "--output", identity_output,
            "--recipient-private", kem_private, "--signer-public", sign_public,
            cwd=work, env=env)
        identity = json.loads(identity_output.read_text())
        if (identity["ip_address"] != "192.0.2.10"
                or identity["hardware_serial"] != "SN-000000-EXAMPLE"):
            raise AssertionError("identity payload mismatch")

        for path in (kem_private, sign_private, python_envelope, cpp_envelope,
                     cpp_output, python_output, identity_envelope, identity_output):
            if stat.S_IMODE(path.stat().st_mode) != 0o600:
                raise AssertionError(f"sensitive file is not 0600: {path}")

        regular_file = work / "not-a-block-device"
        regular_file.write_bytes(b"ordinary file")
        run(cli, "disk", "plan", "--device", regular_file, "--mapper", "smoke-vault",
            cwd=work, env=env, success=False)

    print("wheel smoke: installed CLI, self-tests, signed Python/C++ interop, identity, rejection, permissions, and disk guard passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
