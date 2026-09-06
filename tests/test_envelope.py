import json
import tempfile
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidTag

from qprotect.envelope import (
    Envelope,
    decrypt_envelope,
    encrypt_envelope,
)
from qprotect.exceptions import EnvelopeError
from qprotect.keys import generate_ml_dsa_keypair, generate_ml_kem_keypair
from qprotect.provider import OpenSSLProvider


class EnvelopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="qprotect-tests-")
        root = Path(cls.temp.name)
        cls.recipient_private = root / "recipient-private.pem"
        cls.recipient_public = root / "recipient-public.pem"
        cls.second_private = root / "second-private.pem"
        cls.second_public = root / "second-public.pem"
        cls.signer_private = root / "signer-private.pem"
        cls.signer_public = root / "signer-public.pem"
        cls.provider = OpenSSLProvider()
        cls.recipient_id = generate_ml_kem_keypair(
            cls.recipient_private, cls.recipient_public, cls.provider
        )
        cls.second_id = generate_ml_kem_keypair(cls.second_private, cls.second_public, cls.provider)
        cls.signer_id = generate_ml_dsa_keypair(
            cls.signer_private, cls.signer_public, cls.provider
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_signed_envelope_round_trip(self):
        envelope = encrypt_envelope(
            b"secret",
            recipient_public_keys=[self.recipient_public],
            context="test",
            signer_private_key=self.signer_private,
            provider=self.provider,
        )
        parsed = Envelope.from_json(envelope.to_json())
        self.assertEqual(parsed.context, "test")
        self.assertEqual(parsed.signer_key_id, self.signer_id)
        self.assertEqual(
            decrypt_envelope(
                parsed,
                recipient_private_key=self.recipient_private,
                signer_public_key=self.signer_public,
                provider=self.provider,
            ),
            b"secret",
        )

    def test_multi_recipient_envelope_round_trip(self):
        envelope = encrypt_envelope(
            b"secret",
            recipient_public_keys=[self.recipient_public, self.second_public],
            context="multi",
            provider=self.provider,
        )
        self.assertEqual({item.key_id for item in envelope.recipients}, {self.recipient_id, self.second_id})
        for private_key in (self.recipient_private, self.second_private):
            self.assertEqual(
                decrypt_envelope(
                    envelope,
                    recipient_private_key=private_key,
                    provider=self.provider,
                ),
                b"secret",
            )

    def test_payload_tamper_is_rejected(self):
        envelope = encrypt_envelope(
            b"secret",
            recipient_public_keys=[self.recipient_public],
            context="test",
            provider=self.provider,
        )
        modified = Envelope.from_dict(envelope.to_dict())
        object.__setattr__(modified, "ciphertext", modified.ciphertext + b"\x00")
        with self.assertRaises(EnvelopeError):
            decrypt_envelope(
                modified,
                recipient_private_key=self.recipient_private,
                provider=self.provider,
            )

    def test_signature_mismatch_is_rejected(self):
        envelope = encrypt_envelope(
            b"secret",
            recipient_public_keys=[self.recipient_public],
            context="test",
            signer_private_key=self.signer_private,
            provider=self.provider,
        )
        data = envelope.to_dict()
        signature = bytearray(envelope.signature)
        signature[0] ^= 1
        from base64 import b64encode

        data["signature"] = b64encode(signature).decode("ascii")
        modified = Envelope.from_dict(data)
        with self.assertRaises(EnvelopeError):
            decrypt_envelope(
                modified,
                recipient_private_key=self.recipient_private,
                signer_public_key=self.signer_public,
                provider=self.provider,
            )

    def test_wrong_recipient_is_rejected(self):
        envelope = encrypt_envelope(
            b"secret",
            recipient_public_keys=[self.second_public],
            context="test",
            provider=self.provider,
        )
        with self.assertRaises(EnvelopeError):
            decrypt_envelope(
                envelope,
                recipient_private_key=self.recipient_private,
                provider=self.provider,
            )

    def test_expected_signer_rejects_unsigned_envelope(self):
        envelope = encrypt_envelope(
            b"secret",
            recipient_public_keys=[self.recipient_public],
            context="test",
            provider=self.provider,
        )
        with self.assertRaisesRegex(EnvelopeError, "signature is required"):
            decrypt_envelope(
                envelope,
                recipient_private_key=self.recipient_private,
                signer_public_key=self.signer_public,
                provider=self.provider,
            )

    def test_non_ascii_context_is_rejected_cleanly(self):
        with self.assertRaisesRegex(EnvelopeError, "printable ASCII"):
            encrypt_envelope(
                b"secret",
                recipient_public_keys=[self.recipient_public],
                context="résumé",
                provider=self.provider,
            )

    def test_duplicate_recipient_is_rejected_during_encryption(self):
        with self.assertRaisesRegex(EnvelopeError, "duplicate recipient"):
            encrypt_envelope(
                b"secret",
                recipient_public_keys=[self.recipient_public, self.recipient_public],
                context="test",
                provider=self.provider,
            )

    def test_strict_json_rejects_duplicate_and_unknown_fields(self):
        envelope = encrypt_envelope(
            b"secret",
            recipient_public_keys=[self.recipient_public],
            context="test",
            provider=self.provider,
        )
        text = envelope.to_json(indent=None)
        duplicate = text.replace('"version": 1', '"version": 1, "version": 1', 1)
        with self.assertRaisesRegex(EnvelopeError, "duplicate JSON"):
            Envelope.from_json(duplicate)
        data = json.loads(text)
        data["unknown"] = True
        with self.assertRaisesRegex(EnvelopeError, "unknown fields"):
            Envelope.from_dict(data)


if __name__ == "__main__":
    unittest.main()
