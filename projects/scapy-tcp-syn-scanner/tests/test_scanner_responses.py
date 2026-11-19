
import json
from pathlib import Path
import unittest
from scapy.all import IP, TCP, ICMP

from scanner import TCPScanner


class TestScannerResponses(unittest.TestCase):

    def setUp(self):

        # Load the lecturer's authorised scope
        with open(Path(__file__).resolve().parent / "fixtures" / "valid_scope.json") as file:
            scope = json.load(file)

        # Create a fresh scanner for each test
        self.scanner = TCPScanner(scope)

        # Original simulated SYN probe
        self.probe = IP(
            src="172.28.70.2",
            dst="172.28.70.10"
        ) / TCP(
            sport=51544,
            dport=22,
            flags="S",
            seq=1000
        )

    def test_syn_ack_open(self):

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

        result = self.scanner.classify_response(self.probe, response)

        self.assertEqual(result, "open")

    def test_rst_closed(self):

        response = IP(
            src="172.28.70.10",
            dst="172.28.70.2"
        ) / TCP(
            sport=22,
            dport=51544,
            flags="RA",
            ack=1001
        )

        result = self.scanner.classify_response(self.probe, response)

        self.assertEqual(result, "closed")

    def test_icmp_filtered(self):

        response = IP(
            src="172.28.70.1",
            dst="172.28.70.2"
        ) / ICMP(
            type=3,
            code=13
        ) / self.probe.copy()

        response = IP(bytes(response))

        result = self.scanner.classify_response(self.probe, response)

        self.assertEqual(result, "filtered-or-no-response")

    def test_unrelated_tcp(self):

        response = IP(
            src="172.28.70.10",
            dst="172.28.70.2"
        ) / TCP(
            sport=80,
            dport=51544,
            flags="SA",
            ack=1001
        )

        result = self.scanner.classify_response(self.probe, response)

        self.assertIsNone(result)

    def test_unrelated_icmp(self):

        wrong_probe = self.probe.copy()
        wrong_probe[TCP].dport = 80

        response = IP(
            src="172.28.70.1",
            dst="172.28.70.2"
        ) / ICMP(
            type=3,
            code=13
        ) / wrong_probe

        response = IP(bytes(response))

        result = self.scanner.classify_response(self.probe, response)

        self.assertIsNone(result)

    def test_missing_response(self):

        result = self.scanner.classify_response(self.probe, None)

        self.assertIsNone(result)


    def test_rst_without_ack(self):

        response = IP(
            src="172.28.70.10",
            dst="172.28.70.2"
        ) / TCP(
            sport=22,
            dport=51544,
            flags="R",
            seq=5000
        )

        result = self.scanner.classify_response(
            self.probe, response
        )

        self.assertEqual(result, "closed")


    def test_sequence_wraparound(self):

        # Create a SYN using the largest 32-bit sequence number
        probe = self.probe.copy()
        probe[TCP].seq = 4294967295

        response = IP(
            src="172.28.70.10",
            dst="172.28.70.2"
        ) / TCP(
            sport=22,
            dport=51544,
            flags="SA",
            seq=5000,
            ack=0
        )

        result = self.scanner.classify_response(
            probe, response
        )

        self.assertEqual(result, "open")


    def test_rst_wrong_ack(self):

        response = IP(
            src="172.28.70.10",
            dst="172.28.70.2"
        ) / TCP(
            sport=22,
            dport=51544,
            flags="RA",
            ack=9999
        )

        result = self.scanner.classify_response(
            self.probe, response
        )

        self.assertIsNone(result)
    
    def test_conflicting_tcp_flags(self):
        response = IP(
            src="172.28.70.10",
            dst="172.28.70.2"
        ) / TCP(
            sport=22,
            dport=51544,
            flags="SAR",
            seq=5000,
            ack=1001
        )
        result = self.scanner.classify_response(
            self.probe, response
        )
        self.assertIsNone(result)

if __name__ == "__main__":
    unittest.main(verbosity=2)
