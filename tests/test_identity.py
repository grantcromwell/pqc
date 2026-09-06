import json
import unittest

from qprotect.exceptions import IdentityValidationError
from qprotect.identity import IdentityRecord, validate_identity


class IdentityTests(unittest.TestCase):
    def test_valid_identity_record(self):
        record = validate_identity(
            {
                "ip": "192.0.2.1",
                "mac": "00-1A-2B-3C-4D-5E",
                "serial": "SN-EXAMPLE",
                "uuid": "123e4567-e89b-12d3-a456-426614174000",
                "guid": "{123e4567-e89b-12d3-a456-426614174001}",
                "browser_fingerprint": {"canvas": "hash"},
                "wifi_bssid": "AA.BB.CC.11.22.33",
                "gps": {"latitude": 1.0, "longitude": 2.0, "accuracy_m": 3.0},
                "host": "example",
            }
        )
        self.assertEqual(record.ip_address, "192.0.2.1")
        self.assertEqual(record.mac_address, "00:1a:2b:3c:4d:5e")
        self.assertEqual(record.wifi_bssid, "aa:bb:cc:11:22:33")
        self.assertEqual(record.guid, "123e4567-e89b-12d3-a456-426614174001")
        self.assertEqual(record.additional["host"], "example")

    def test_json_round_trip(self):
        payload = json.dumps(
            {"ip": "2001:db8::1", "serial": "SN-1", "gps": {"latitude": 0, "longitude": 0}}
        )
        record = IdentityRecord.from_json(payload)
        self.assertEqual(record.ip_address, "2001:db8::1")
        parsed = json.loads(record.to_payload())
        self.assertEqual(parsed["ip_address"], "2001:db8::1")

    def test_invalid_values_do_not_echo_input(self):
        cases = [
            {"ip": "not-an-ip"},
            {"mac": "not-a-mac"},
            {"uuid": "not-a-uuid"},
            {"serial": ""},
            {"gps": {"latitude": 91, "longitude": 0}},
            {"gps": {"latitude": 0, "longitude": 181}},
        ]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(IdentityValidationError) as context:
                validate_identity(case)
            self.assertNotIn(str(case), str(context.exception))


if __name__ == "__main__":
    unittest.main()
