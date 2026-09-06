import os
from pathlib import Path
import stat
import tempfile
import unittest

from qprotect.exceptions import QProtectError
from qprotect.io_utils import atomic_write


class AtomicWriteTests(unittest.TestCase):
    def test_restrictive_mode_no_clobber_and_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "secret.bin"
            atomic_write(output, b"first")
            self.assertEqual(output.read_bytes(), b"first")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

            with self.assertRaises(QProtectError):
                atomic_write(output, b"second")
            self.assertEqual(output.read_bytes(), b"first")

            atomic_write(output, b"second", overwrite=True)
            self.assertEqual(output.read_bytes(), b"second")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_force_replaces_symlink_without_touching_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.write_bytes(b"target")
            output = root / "output"
            os.symlink(target, output)

            atomic_write(output, b"replacement", overwrite=True)

            self.assertFalse(output.is_symlink())
            self.assertEqual(output.read_bytes(), b"replacement")
            self.assertEqual(target.read_bytes(), b"target")


if __name__ == "__main__":
    unittest.main()
