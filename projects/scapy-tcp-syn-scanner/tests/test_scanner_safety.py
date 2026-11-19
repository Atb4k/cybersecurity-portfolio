
import json
from pathlib import Path
import unittest
from scapy.all import IP, TCP

from scanner import TCPScanner


class TestScannerSafety(unittest.TestCase):

    def setUp(self):

        with open(
            Path(__file__).resolve().parent / "fixtures" / "valid_scope.json",
            "r",
            encoding="utf-8"
        ) as file:
            self.scope = json.load(file)

        self.scanner = TCPScanner(self.scope)

        self.probe = IP(
            src="172.28.70.2",
            dst="172.28.70.10"
        ) / TCP(
            sport=51544,
            dport=22,
            flags="S",
            seq=1000
        )

    def test_invalid_scope_values(self):

        test_cases = [
            ("Wrong target", "target", "8.8.8.8"),
            ("Wrong scope ID", "scope_id", "fake-id"),
            ("Duplicate ports", "ports", [22, 80, 80]),
            ("Unauthorised port", "ports", [22, 3306]),
            ("Excessive rate", "maximum_rate_pps", 100),
            ("Boolean rate", "maximum_rate_pps", True),
            ("Too many attempts", "maximum_attempts", 3),
            ("Excessive timeout", "timeout_seconds", 5.0),
            ("Wrong interface", "interface", "eth1"),
            ("Wrong option", "option", "device-map")
        ]

        for name, field, invalid_value in test_cases:

            with self.subTest(case=name):

                invalid_scope = dict(self.scope)
                invalid_scope[field] = invalid_value

                with self.assertRaises(ValueError):
                    TCPScanner(invalid_scope)

    def test_missing_scope_id(self):

        invalid_scope = dict(self.scope)
        invalid_scope.pop("scope_id")

        with self.assertRaises(ValueError):
            TCPScanner(invalid_scope)

    def test_unauthorised_probe_port(self):

        with self.assertRaises(ValueError):
            self.scanner.build_syn_probe(3306)

    def test_unrelated_tcp_wrong_ack(self):

        response = IP(
            src="172.28.70.10",
            dst="172.28.70.2"
        ) / TCP(
            sport=22,
            dport=51544,
            flags="SA",
            seq=5000,
            ack=9999
        )

        result = self.scanner.classify_response(
            self.probe, response
        )

        self.assertIsNone(result)

    def test_unrelated_tcp_wrong_source(self):

        response = IP(
            src="172.28.70.99",
            dst="172.28.70.2"
        ) / TCP(
            sport=22,
            dport=51544,
            flags="SA",
            seq=5000,
            ack=1001
        )

        result = self.scanner.classify_response(
            self.probe, response
        )

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
