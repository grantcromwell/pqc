#!/usr/bin/env python3
"""Cross-implementation integration tests for the qprotect C++ module.

Runs the C++ algorithm self-test and unit test binaries, then verifies that
the C++ library interoperates with the Python reference implementation in
both directions: keys, envelopes, signatures, serialization, tamper
rejection, and edge cases. Every envelope produced by one implementation
must decrypt (or be rejected) by the other.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "cpp" / "build" / "qprotect_cpp_tool"
SELFTEST = ROOT / "cpp" / "build" / "qprotect_cpp_selftest"
UNITTESTS = ROOT / "cpp" / "build" / "qprotect_cpp_unittests"

sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402

from qprotect.envelope import Envelope, decrypt_envelope, encrypt_envelope  # noqa: E402
from qprotect.exceptions import EnvelopeError  # noqa: E402
from qprotect.identity import IdentityRecord  # noqa: E402
from qprotect.provider import OpenSSLProvider  # noqa: E402

CHECKS = 0
FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    global CHECKS
    CHECKS += 1
    if condition:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}" + (f" ({detail})" if detail else ""))
        FAILURES.append(name)


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "qprotect", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


def cpp_tool(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([str(TOOL), *args], capture_output=True, text=True)


def expect_success(result: subprocess.CompletedProcess, what: str) -> subprocess.CompletedProcess:
    if result.returncode != 0:
        print(f"  FAIL {what}: exit {result.returncode}")
        print(f"       stdout: {result.stdout.strip()[:400]}")
        print(f"       stderr: {result.stderr.strip()[:400]}")
        FAILURES.append(what)
        CHECKS += 1
    else:
        check(what, True)
    return result


def expect_failure(result: subprocess.CompletedProcess, what: str) -> subprocess.CompletedProcess:
    check(what, result.returncode != 0, f"unexpectedly succeeded: {result.stdout[:200]}")


def test_cpp_binaries() -> None:
    print("[1] C++ binaries")
    expect_success(subprocess.run([str(SELFTEST)], capture_output=True, text=True),
                   "C++ algorithm self-test passes")
    expect_success(subprocess.run([str(UNITTESTS)], capture_output=True, text=True),
                   "C++ unit tests pass")


def test_hkdf_cross_verification() -> None:
    print("[2] HKDF known-answer cross-verification")
    # The C++ self-test embeds this exact vector. Derive it here with the
    # Python cryptography Rust HKDF implementation, which is independent of
    # the OpenSSL EVP_KDF used by the C++ module.
    derived = HKDF(
        algorithm=hashes.SHA384(), length=32, salt=b"salt", info=b"info"
    ).derive(b"secret")
    check(
        "embedded C++ HKDF-SHA-384 vector matches independent implementation",
        derived == bytes.fromhex(
            "29c042775183ec5dbc2c085eb49502b15d9e8abe4a4c1ef98e8e0fb95ad5f6a9"
        ),
    )


def test_keygen_interop(work: Path) -> tuple[dict[str, Path], dict[str, Path]]:
    print("[3] key generation interop")
    python_keys = {
        "kem_private": work / "py-kem-private.pem",
        "kem_public": work / "py-kem-public.pem",
        "sign_private": work / "py-sign-private.pem",
        "sign_public": work / "py-sign-public.pem",
    }
    cpp_keys = {
        "kem_private": work / "cpp-kem-private.pem",
        "kem_public": work / "cpp-kem-public.pem",
        "sign_private": work / "cpp-sign-private.pem",
        "sign_public": work / "cpp-sign-public.pem",
    }

    expect_success(run_cli("keygen", "--type", "kem",
                           "--private", str(python_keys["kem_private"]),
                           "--public", str(python_keys["kem_public"])),
                   "Python CLI generates ML-KEM-1024 keypair")
    expect_success(run_cli("keygen", "--type", "sign",
                           "--private", str(python_keys["sign_private"]),
                           "--public", str(python_keys["sign_public"])),
                   "Python CLI generates ML-DSA-87 keypair")
    expect_success(cpp_tool("keygen", "--type", "kem",
                            "--private", str(cpp_keys["kem_private"]),
                            "--public", str(cpp_keys["kem_public"])),
                   "C++ tool generates ML-KEM-1024 keypair")
    expect_success(cpp_tool("keygen", "--type", "sign",
                            "--private", str(cpp_keys["sign_private"]),
                            "--public", str(cpp_keys["sign_public"])),
                   "C++ tool generates ML-DSA-87 keypair")

    # Private keys must be owner-only in both implementations.
    for label, keys in (("python", python_keys), ("cpp", cpp_keys)):
        mode = stat.S_IMODE(os.stat(keys["kem_private"]).st_mode)
        check(f"{label} private key file is 0600", mode == 0o600, oct(mode))

    # OpenSSL itself must accept the C++ tool's PEM output.
    probe = subprocess.run(
        ["openssl", "pkey", "-pubin", "-in", str(cpp_keys["kem_public"]), "-noout"],
        capture_output=True, text=True,
    )
    check("OpenSSL parses C++ tool public key PEM", probe.returncode == 0,
          probe.stderr.strip()[:200])

    # key_id agreement: both implementations must derive the same key_id.
    provider = OpenSSLProvider()
    cpp_keygen = cpp_tool("keygen", "--type", "kem",
                          "--private", str(work / "cpp-kem2-private.pem"),
                          "--public", str(work / "cpp-kem2-public.pem"))
    cpp_reported = cpp_keygen.stdout.strip().split()[-1]
    python_computed = provider.key_id(work / "cpp-kem2-public.pem")
    check("key_id agreement (C++ reports, Python computes)", cpp_reported == python_computed,
          f"{cpp_reported} vs {python_computed}")
    return python_keys, cpp_keys


def test_python_to_cpp(work: Path, payload: bytes,
                       python_keys: dict[str, Path], cpp_keys: dict[str, Path]) -> None:
    print("[4] Python encrypts -> C++ decrypts")
    payload_path = work / "payload-python.bin"
    payload_path.write_bytes(payload)
    envelope_path = work / "python-made.qpe"
    recovered_path = work / "recovered-cpp.bin"

    expect_success(run_cli(
        "encrypt",
        "--input", str(payload_path),
        "--output", str(envelope_path),
        "--recipient", str(cpp_keys["kem_public"]),
        "--recipient", str(python_keys["kem_public"]),
        "--signer", str(python_keys["sign_private"]),
        "--context", "interop-python-to-cpp",
    ), "Python CLI encrypts for a C++-generated recipient, signed")
    check("Python envelope file is 0600",
          stat.S_IMODE(envelope_path.stat().st_mode) == 0o600)

    expect_success(cpp_tool(
        "decrypt",
        "--input", str(envelope_path),
        "--output", str(recovered_path),
        "--recipient-private", str(cpp_keys["kem_private"]),
        "--signer-public", str(python_keys["sign_public"]),
    ), "C++ tool decrypts Python-made envelope (C++ recipient)")
    check("payloads match", recovered_path.read_bytes() == payload)
    check("C++ decrypted output file is 0600",
          stat.S_IMODE(recovered_path.stat().st_mode) == 0o600)

    expect_success(cpp_tool(
        "decrypt",
        "--input", str(envelope_path),
        "--output", str(work / "recovered-cpp2.bin"),
        "--recipient-private", str(python_keys["kem_private"]),
        "--signer-public", str(python_keys["sign_public"]),
    ), "C++ tool decrypts Python-made envelope (Python recipient)")
    check("payloads match (second recipient)",
          (work / "recovered-cpp2.bin").read_bytes() == payload)

    # Identity record round trip through the identity CLI.
    identity_path = ROOT / "examples" / "identity.json"
    identity_envelope = work / "identity.qpe"
    identity_recovered = work / "identity-recovered.json"
    expect_success(run_cli(
        "identity-encrypt",
        "--input", str(identity_path),
        "--output", str(identity_envelope),
        "--recipient", str(cpp_keys["kem_public"]),
        "--signer", str(python_keys["sign_private"]),
    ), "Python CLI identity-encrypt for C++ recipient")
    expect_success(cpp_tool(
        "decrypt",
        "--input", str(identity_envelope),
        "--output", str(identity_recovered),
        "--recipient-private", str(cpp_keys["kem_private"]),
        "--signer-public", str(python_keys["sign_public"]),
    ), "C++ tool decrypts identity envelope")
    # identity-encrypt seals the canonical record (normalized field names),
    # not the raw input file, so compare against the canonical payload.
    expected_payload = IdentityRecord.from_json(
        identity_path.read_bytes()
    ).to_payload()
    check("identity record round-trips canonical payload",
          identity_recovered.read_bytes() == expected_payload)


def test_cpp_to_python(work: Path, payload: bytes,
                       python_keys: dict[str, Path], cpp_keys: dict[str, Path]) -> None:
    print("[5] C++ encrypts -> Python decrypts")
    payload_path = work / "payload-cpp.bin"
    payload_path.write_bytes(payload)
    envelope_path = work / "cpp-made.qpe"
    recovered_path = work / "recovered-python.bin"

    expect_success(cpp_tool(
        "encrypt",
        "--input", str(payload_path),
        "--output", str(envelope_path),
        "--recipient", str(python_keys["kem_public"]),
        "--recipient", str(cpp_keys["kem_public"]),
        "--signer", str(cpp_keys["sign_private"]),
        "--context", "interop-cpp-to-python",
    ), "C++ tool encrypts for a Python-generated recipient, signed")
    check("C++ envelope file is 0600",
          stat.S_IMODE(envelope_path.stat().st_mode) == 0o600)
    expect_failure(cpp_tool(
        "encrypt",
        "--input", str(payload_path),
        "--output", str(envelope_path),
        "--recipient", str(python_keys["kem_public"]),
        "--context", "interop-no-clobber",
    ), "C++ tool refuses to overwrite an envelope without --force")

    expect_success(run_cli(
        "decrypt",
        "--input", str(envelope_path),
        "--output", str(recovered_path),
        "--recipient-private", str(python_keys["kem_private"]),
        "--signer-public", str(cpp_keys["sign_public"]),
    ), "Python CLI decrypts C++-made envelope (Python recipient)")
    check("payloads match", recovered_path.read_bytes() == payload)
    check("Python decrypted output file is 0600",
          stat.S_IMODE(recovered_path.stat().st_mode) == 0o600)

    expect_success(run_cli(
        "decrypt",
        "--input", str(envelope_path),
        "--output", str(work / "recovered-python2.bin"),
        "--recipient-private", str(cpp_keys["kem_private"]),
        "--signer-public", str(cpp_keys["sign_public"]),
    ), "Python CLI decrypts C++-made envelope (C++ recipient)")
    check("payloads match (second recipient)",
          (work / "recovered-python2.bin").read_bytes() == payload)


def test_serialization_equivalence(work: Path, cpp_keys: dict[str, Path]) -> None:
    print("[6] serialization byte-equivalence")
    # Re-serializing a C++ envelope with the Python implementation must be
    # byte-identical: same key order, indentation, separators, and escaping.
    payload_path = work / "payload-cpp.bin"
    envelope_path = work / "cpp-made.qpe"
    text = envelope_path.read_text()
    envelope = Envelope.from_json(text)
    check("Python re-serialization of C++ envelope is byte-identical",
          envelope.to_json() == text)

    # The canonical signature material and AAD must also agree, which the
    # successful signed decrypts already proved; assert it directly too.
    material = envelope.signature_material().decode("utf-8")
    parsed = json.loads(material)
    check("signature material is canonical JSON",
          material == json.dumps(parsed, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=False))
    check("signature material carries no signature field", "signature" not in parsed)
    check("signature material includes signer_key_id",
          parsed["signer_key_id"] == envelope.signer_key_id)

    # Unsigned C++ envelope: same byte-equivalence.
    unsigned_path = work / "cpp-unsigned.qpe"
    expect_success(cpp_tool(
        "encrypt",
        "--input", str(payload_path),
        "--output", str(unsigned_path),
        "--recipient", str(cpp_keys["kem_public"]),
        "--context", "interop-unsigned",
    ), "C++ tool encrypts unsigned envelope")
    unsigned_text = unsigned_path.read_text()
    unsigned = Envelope.from_json(unsigned_text)
    check("Python re-serialization of unsigned C++ envelope is byte-identical",
          unsigned.to_json() == unsigned_text)
    check("unsigned envelope has no signature", unsigned.signature is None)


def test_tamper_rejection(work: Path, python_keys: dict[str, Path],
                          cpp_keys: dict[str, Path]) -> None:
    print("[7] tamper rejection across implementations")

    # Tamper a C++-made envelope and require the Python decrypt to fail.
    envelope_path = work / "cpp-made.qpe"
    envelope = Envelope.from_json(envelope_path.read_text())
    broken = json.loads(envelope_path.read_text())
    raw = bytearray(base64.b64decode(broken["ciphertext"]))
    raw[0] ^= 0x01
    broken["ciphertext"] = base64.b64encode(bytes(raw)).decode("ascii")
    broken_path = work / "cpp-made-tampered.qpe"
    broken_path.write_text(json.dumps(broken, indent=2, sort_keys=True))
    try:
        decrypt_envelope(
            Envelope.from_json(broken_path.read_text()),
            recipient_private_key=str(python_keys["kem_private"]),
            signer_public_key=str(cpp_keys["sign_public"]),
        )
        check("Python rejects tampered C++ ciphertext", False)
    except EnvelopeError:
        check("Python rejects tampered C++ ciphertext", True)

    # Tamper the signature of a C++-made envelope.
    broken_sig = json.loads(envelope_path.read_text())
    sig = bytearray(base64.b64decode(broken_sig["signature"]))
    sig[0] ^= 0x01
    broken_sig["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
    sig_path = work / "cpp-made-bad-sig.qpe"
    sig_path.write_text(json.dumps(broken_sig, indent=2, sort_keys=True))
    try:
        decrypt_envelope(
            Envelope.from_json(sig_path.read_text()),
            recipient_private_key=str(python_keys["kem_private"]),
            signer_public_key=str(cpp_keys["sign_public"]),
        )
        check("Python rejects tampered C++ signature", False)
    except EnvelopeError:
        check("Python rejects tampered C++ signature", True)

    # Tamper a Python-made envelope and require the C++ decrypt to fail.
    python_envelope_path = work / "python-made.qpe"
    broken2 = json.loads(python_envelope_path.read_text())
    wrapped = bytearray(base64.b64decode(broken2["recipients"][0]["wrapped_key"]))
    wrapped[0] ^= 0x01
    broken2["recipients"][0]["wrapped_key"] = base64.b64encode(bytes(wrapped)).decode("ascii")
    broken2_path = work / "python-made-tampered.qpe"
    broken2_path.write_text(json.dumps(broken2, indent=2, sort_keys=True))
    expect_failure(cpp_tool(
        "decrypt",
        "--input", str(broken2_path),
        "--output", str(work / "should-not-exist.bin"),
        "--recipient-private", str(cpp_keys["kem_private"]),
        "--signer-public", str(python_keys["sign_public"]),
    ), "C++ tool rejects tampered Python wrapped key")

    # Wrong recipient key: C++ tool must refuse a Python-made envelope.
    expect_failure(cpp_tool(
        "decrypt",
        "--input", str(python_envelope_path),
        "--output", str(work / "should-not-exist2.bin"),
        "--recipient-private", str(work / "cpp-kem2-private.pem"),
        "--signer-public", str(python_keys["sign_public"]),
    ), "C++ tool rejects wrong recipient private key")


def test_edge_cases(work: Path, python_keys: dict[str, Path],
                    cpp_keys: dict[str, Path]) -> None:
    print("[8] edge cases")
    # Zero-byte payload, both directions.
    empty_path = work / "empty.bin"
    empty_path.write_bytes(b"")

    cpp_empty_envelope = work / "cpp-empty.qpe"
    expect_success(cpp_tool(
        "encrypt",
        "--input", str(empty_path),
        "--output", str(cpp_empty_envelope),
        "--recipient", str(python_keys["kem_public"]),
        "--context", "interop-empty",
    ), "C++ tool encrypts empty payload")
    recovered_empty = work / "recovered-empty.bin"
    expect_success(run_cli(
        "decrypt",
        "--input", str(cpp_empty_envelope),
        "--output", str(recovered_empty),
        "--recipient-private", str(python_keys["kem_private"]),
    ), "Python CLI decrypts empty C++ envelope")
    check("empty payload round-trips (C++ -> Python)", recovered_empty.read_bytes() == b"")

    python_empty_envelope = work / "python-empty.qpe"
    expect_success(run_cli(
        "encrypt",
        "--input", str(empty_path),
        "--output", str(python_empty_envelope),
        "--recipient", str(cpp_keys["kem_public"]),
        "--context", "interop-empty",
    ), "Python CLI encrypts empty payload")
    recovered_empty2 = work / "recovered-empty2.bin"
    expect_success(cpp_tool(
        "decrypt",
        "--input", str(python_empty_envelope),
        "--output", str(recovered_empty2),
        "--recipient-private", str(cpp_keys["kem_private"]),
    ), "C++ tool decrypts empty Python envelope")
    check("empty payload round-trips (Python -> C++)", recovered_empty2.read_bytes() == b"")

    # Large payload (1 MiB) to exercise the chunked AEAD update path.
    large = secrets.token_bytes(1024 * 1024)
    large_path = work / "large.bin"
    large_path.write_bytes(large)
    large_envelope = work / "large.qpe"
    expect_success(cpp_tool(
        "encrypt",
        "--input", str(large_path),
        "--output", str(large_envelope),
        "--recipient", str(python_keys["kem_public"]),
        "--context", "interop-large",
    ), "C++ tool encrypts 1 MiB payload")
    recovered_large = work / "recovered-large.bin"
    expect_success(run_cli(
        "decrypt",
        "--input", str(large_envelope),
        "--output", str(recovered_large),
        "--recipient-private", str(python_keys["kem_private"]),
    ), "Python CLI decrypts 1 MiB envelope")
    check("1 MiB payload round-trips", recovered_large.read_bytes() == large)

    # Context with quotes and backslashes: escaping must agree on both sides.
    tricky_path = work / "tricky.bin"
    tricky_path.write_bytes(b"tricky")
    tricky_envelope = work / "tricky.qpe"
    expect_success(cpp_tool(
        "encrypt",
        "--input", str(tricky_path),
        "--output", str(tricky_envelope),
        "--recipient", str(python_keys["kem_public"]),
        "--context", 'con"text\\slash',
    ), "C++ tool encrypts with quoting-heavy context")
    recovered_tricky = work / "recovered-tricky.bin"
    expect_success(run_cli(
        "decrypt",
        "--input", str(tricky_envelope),
        "--output", str(recovered_tricky),
        "--recipient-private", str(python_keys["kem_private"]),
    ), "Python CLI decrypts quoting-heavy context envelope")
    check("quoted context round-trips", recovered_tricky.read_bytes() == b"tricky")


def test_python_reference_suite() -> None:
    print("[9] Python reference suite")
    expect_success(run_cli("selftest"), "Python CLI selftest passes")
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
        cwd=ROOT, capture_output=True, text=True,
    )
    check("Python unittest suite passes", result.returncode == 0,
          result.stderr.strip()[-200:])


def main() -> int:
    for binary in (TOOL, SELFTEST, UNITTESTS):
        if not binary.exists():
            print(f"missing binary: {binary} (run: make -C cpp)")
            return 2

    with tempfile.TemporaryDirectory(prefix="qprotect-interop-") as tmp:
        work = Path(tmp)
        test_cpp_binaries()
        test_hkdf_cross_verification()
        python_keys, cpp_keys = test_keygen_interop(work)
        payload = secrets.token_bytes(64 * 1024)
        test_python_to_cpp(work, payload, python_keys, cpp_keys)
        test_cpp_to_python(work, payload, python_keys, cpp_keys)
        test_serialization_equivalence(work, cpp_keys)
        test_tamper_rejection(work, python_keys, cpp_keys)
        test_edge_cases(work, python_keys, cpp_keys)
        test_python_reference_suite()

    print(f"\nintegration: {CHECKS} checks, {len(FAILURES)} failures")
    if FAILURES:
        for name in FAILURES:
            print(f"  failed: {name}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
