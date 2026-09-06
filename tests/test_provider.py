import unittest

from qprotect.constants import AEAD, Hash, KDF, KEM, Signature
from qprotect.nist_acvp_vectors import ACVP_REVISION
from qprotect.provider import OpenSSLProvider


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.provider = OpenSSLProvider()

    def test_provider_capabilities(self):
        info = self.provider.info()
        self.assertTrue(info.ml_kem_1024)
        self.assertTrue(info.ml_dsa_87)
        self.assertIn("OpenSSL", info.openssl_version)

    def test_assert_ready(self):
        self.provider.assert_ready()
        self.assertTrue(self.provider.info().algorithm_self_tests_passed)
        self.assertEqual(self.provider.info().nist_acvp_revision, ACVP_REVISION)

    def test_random_bytes(self):
        data = self.provider.random_bytes(32)
        self.assertEqual(len(data), 32)
        self.assertNotEqual(data, self.provider.random_bytes(32))

    def test_hkdf_and_digest(self):
        secret = bytes(range(32))
        derived = self.provider.derive_key(
            secret,
            salt=b"test-salt",
            info=b"test-info",
            length=32,
        )
        self.assertEqual(len(derived), 32)
        self.assertEqual(len(self.provider.digest(b"test", Hash.SHA384)), 48)
        self.assertEqual(len(self.provider.digest(b"test", Hash.SHA512)), 64)

    def test_aead_round_trip(self):
        key = self.provider.random_bytes(32)
        nonce = self.provider.random_bytes(12)
        ciphertext, tag = self.provider.aead_encrypt(key, nonce, b"payload", b"aad")
        self.assertEqual(
            self.provider.aead_decrypt(key, nonce, ciphertext, tag, b"aad"),
            b"payload",
        )

    def test_aead_tamper_rejection(self):
        key = self.provider.random_bytes(32)
        nonce = self.provider.random_bytes(12)
        ciphertext, tag = self.provider.aead_encrypt(key, nonce, b"payload", b"aad")
        modified = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
        with self.assertRaises(Exception):
            self.provider.aead_decrypt(key, nonce, modified, tag, b"aad")

    def test_capability_report_does_not_claim_fips_status(self):
        report = self.provider.info()
        self.assertFalse(hasattr(report, "fips_provider_detected"))


if __name__ == "__main__":
    unittest.main()
