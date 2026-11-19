
import json
from pathlib import Path
import unittest
from scapy.all import IP, TCP

from scanner import TCPScanner


class TestRSTCleanup(unittest.TestCase):

    def setUp(self):

        with open(
            Path(__file__).resolve().parent / "fixtures" / "valid_scope.json",
            "r",
            encoding="utf-8"
        ) as file:
            scope = json.load(file)

        self.scanner = TCPScanner(scope)

        self.probe = IP(
            src="172.28.70.2",
            dst="172.28.70.10"
        ) / TCP(
            sport=51544,
            dport=22,
            flags="S",
            seq=1000
        )

    def test_rst_for_open_port(self):

        response = IP(
            src="172.28.70.10",
            dst="172.28.70.2"
        ) / TCP(
            sport=22,
            dport=51544,
            flags="SA",
            seq=5000,
            ack=1001
        )

        rst = self.scanner.build_rst_cleanup(
            self.probe, response
        )

        self.assertIsNotNone(rst)

        self.assertEqual(str(rst[TCP].flags), "RA")
        self.assertEqual(rst[IP].dst, "172.28.70.10")
        self.assertEqual(rst[TCP].sport, 51544)
        self.assertEqual(rst[TCP].dport, 22)
        self.assertEqual(rst[TCP].seq, 1001)
        self.assertEqual(rst[TCP].ack, 5001)

    def test_no_cleanup_for_closed_port(self):

        response = IP(
            src="172.28.70.10",
            dst="172.28.70.2"
        ) / TCP(
            sport=22,
            dport=51544,
            flags="RA",
            ack=1001
        )

        rst = self.scanner.build_rst_cleanup(
            self.probe, response
        )

        self.assertIsNone(rst)

    def test_no_cleanup_for_unrelated_reply(self):

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

        rst = self.scanner.build_rst_cleanup(
            self.probe, response
        )

        self.assertIsNone(rst)


if __name__ == "__main__":
    unittest.main(verbosity=2)
