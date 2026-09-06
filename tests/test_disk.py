import unittest
from pathlib import Path
from unittest.mock import patch

from qprotect.disk import (
    CONFIRM_FORMAT,
    LUKS2Plan,
    build_luks2_plan,
    command_strings,
    confirmation_for,
    execute_luks2_format,
    whole_disk_profile,
)


class DiskPlanTests(unittest.TestCase):
    def test_luks2_command_profile(self):
        plan = LUKS2Plan(device=Path("/dev/nvme0n1p4"), mapper_name="vault")
        args = plan.format_args()
        self.assertIn("--type", args)
        self.assertIn("luks2", args)
        self.assertIn("--cipher", args)
        self.assertIn("aes-xts-plain64", args)
        self.assertIn("--key-size", args)
        self.assertIn("512", args)
        self.assertIn("--pbkdf", args)
        self.assertIn("argon2id", args)
        profile = whole_disk_profile()
        self.assertEqual(profile["key_bits"], 512)

    def test_command_strings_are_shell_quoted(self):
        plan = LUKS2Plan(device=Path("/dev/example disk"), mapper_name="vault")
        commands = command_strings(plan)
        self.assertTrue(commands[0].startswith("cryptsetup luksFormat"))
        self.assertIn("'/dev/example disk'", commands[0])

    def test_confirmation_is_deliberate(self):
        with (
            patch("qprotect.disk._validate_cryptsetup"),
            patch(
                "qprotect.disk._validate_block_device",
                return_value=(Path("/dev/fake"), (7, 1)),
            ),
        ):
            first = build_luks2_plan("/dev/fake", mapper_name="vault")
            second = build_luks2_plan("/dev/fake", mapper_name="vault", iter_time_ms=6000)
            first_confirmation = confirmation_for(first)
            second_confirmation = confirmation_for(second)
        self.assertTrue(first_confirmation.startswith(f"{CONFIRM_FORMAT}-fake-"))
        self.assertNotEqual(first_confirmation, second_confirmation)

    def test_directly_constructed_plan_cannot_execute(self):
        plan = LUKS2Plan(device=Path("/dev/fake"), mapper_name="vault")
        with self.assertRaisesRegex(Exception, "build_luks2_plan"):
            execute_luks2_format(plan, confirmation="anything")


if __name__ == "__main__":
    unittest.main()
