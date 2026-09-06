import contextlib
import io
import json
import unittest

from qprotect.cli import main


class CLITests(unittest.TestCase):
    def test_doctor_reports_expected_algorithms(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["doctor"])
        self.assertEqual(code, 0)
        report = json.loads(output.getvalue())
        self.assertTrue(report["provider"]["ml_kem_1024"])
        self.assertTrue(report["provider"]["ml_dsa_87"])
        self.assertTrue(report["provider"]["algorithm_self_tests_passed"])
        self.assertEqual(
            report["provider"]["nist_acvp_revision"],
            "975de31eb83d87039ec88934fdc47d8c312b892d",
        )
        self.assertEqual(report["profile"]["suite"]["kem"], "ML-KEM-1024")
        self.assertEqual(report["profile"]["suite"]["signature"], "ML-DSA-87")
        self.assertNotIn("fips_target", report["profile"])
        self.assertIn("Not FIPS 140-3 validated", report["profile"]["validation_status"])

    def test_version_flag(self):
        with self.assertRaises(SystemExit) as context:
            main(["--version"])
        self.assertEqual(context.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
