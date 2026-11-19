import json
from pathlib import Path
import unittest
from unittest.mock import patch
from scapy.all import IP, TCP

from scanner import TCPScanner


class TestProbeIdentity(unittest.TestCase):

    def test_distinct_probe_identifiers(self):

        with open(Path(__file__).resolve().parent / "fixtures" / "valid_scope.json") as file:
            scope = json.load(file)

        scanner = TCPScanner(scope)

        # Construct two SYN packets for the same target port
        # Simulate the authorised interface for this unit test
        with patch.object(
            scanner,
            "check_runtime_interface",
            return_value="172.28.70.2"
        ):
            # Construct two SYN packets for the same target port
            first = scanner.build_syn_probe(22)
            second = scanner.build_syn_probe(22)

        self.assertEqual(first[IP].src, "172.28.70.2")
        self.assertEqual(first[IP].dst, "172.28.70.10")

        self.assertNotEqual(first[TCP].sport, second[TCP].sport)
        self.assertNotEqual(first[TCP].seq, second[TCP].seq)

        # A dry-run plan must not allocate further identifiers
        plan1 = scanner.create_scan_plan()
        plan2 = scanner.create_scan_plan()

        self.assertEqual(plan1, plan2)
        self.assertEqual(len(scanner.used_source_ports), 2)
        self.assertEqual(len(scanner.used_sequences), 2)

        print("\nFirst source port:", first[TCP].sport)
        print("First sequence:", first[TCP].seq)
        print("Second source port:", second[TCP].sport)
        print("Second sequence:", second[TCP].seq)


if __name__ == "__main__":
    unittest.main(verbosity=2)
