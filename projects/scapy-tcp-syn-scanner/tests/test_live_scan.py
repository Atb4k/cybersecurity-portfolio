import json
from pathlib import Path
import unittest
from unittest.mock import patch

from scapy.all import IP, TCP
from scanner import TCPScanner


class TestLiveScan(unittest.TestCase):

    def setUp(self):
        with open(
            Path(__file__).resolve().parent / "fixtures" / "valid_scope.json",
            "r",
            encoding="utf-8"
        ) as file:
            scope = json.load(file)

        self.scanner = TCPScanner(scope)

        # Simulate a valid source IP without depending on routing.
        self.interface_patch = patch.object(
            self.scanner,
            "check_runtime_interface",
            return_value="172.28.70.2"
        )
        self.interface_patch.start()
        self.addCleanup(self.interface_patch.stop)

        # Avoid unnecessary waiting during unit tests.
        self.timing_patch = patch.object(
            self.scanner,
            "wait_for_probe_slot"
        )
        self.timing_patch.start()
        self.addCleanup(self.timing_patch.stop)

    def test_open_port(self):

        def fake_syn_ack(probe, **kwargs):
            return IP(
                src=probe[IP].dst,
                dst=probe[IP].src
            ) / TCP(
                sport=probe[TCP].dport,
                dport=probe[TCP].sport,
                flags="SA",
                seq=5000,
                ack=(probe[TCP].seq + 1) % (2**32)
            )

        with patch("scanner.sr1", side_effect=fake_syn_ack) as mock_sr1:
            with patch("scanner.send") as mock_send:

                result = self.scanner.scan_port(22)

                self.assertEqual(result["state"], "open")
                self.assertEqual(result["attempts"], 1)
                self.assertEqual(result["observations"][0]["evidence"], "syn-ack")

                mock_sr1.assert_called_once()
                mock_send.assert_called_once()

                rst = mock_send.call_args.args[0]
                self.assertEqual(int(rst[TCP].flags), 0x14)

    def test_closed_port(self):

        def fake_rst(probe, **kwargs):
            return IP(
                src=probe[IP].dst,
                dst=probe[IP].src
            ) / TCP(
                sport=probe[TCP].dport,
                dport=probe[TCP].sport,
                flags="RA",
                ack=(probe[TCP].seq + 1) % (2**32)
            )

        with patch("scanner.sr1", side_effect=fake_rst) as mock_sr1:
            with patch("scanner.send") as mock_send:

                result = self.scanner.scan_port(80)

                self.assertEqual(result["state"], "closed")
                self.assertEqual(result["attempts"], 1)

                mock_sr1.assert_called_once()
                mock_send.assert_not_called()

    def test_timeout_and_retry(self):

        with patch("scanner.sr1", return_value=None) as mock_sr1:
            with patch("scanner.send") as mock_send:

                result = self.scanner.scan_port(443)

                self.assertEqual(
                    result["state"],
                    "filtered-or-no-response"
                )
                self.assertEqual(result["attempts"], 2)
                self.assertEqual(len(result["observations"]), 2)

                self.assertEqual(mock_sr1.call_count, 2)
                mock_send.assert_not_called()
                
    def test_unrelated_response_then_open(self):
        reply_count = 0
        def fake_reply(probe, **kwargs):
            nonlocal reply_count
            reply_count += 1
            # First response comes from the wrong IP.
            if reply_count == 1:
                return IP(
                    src="172.28.70.11",
                    dst=probe[IP].src
                ) / TCP(
                    sport=probe[TCP].dport,
                    dport=probe[TCP].sport,
                    flags="SA",
                    seq=5000,
                    ack=(probe[TCP].seq + 1) % (2**32)
                )
            # Second response correctly matches the probe.
            return IP(
                src=probe[IP].dst,
                dst=probe[IP].src
            ) / TCP(
                sport=probe[TCP].dport,
                dport=probe[TCP].sport,
                flags="SA",
                seq=6000,
                ack=(probe[TCP].seq + 1) % (2**32)
            )
        with patch("scanner.sr1", side_effect=fake_reply) as mock_sr1:
            with patch("scanner.send") as mock_send:
                result = self.scanner.scan_port(22)
                self.assertEqual(result["state"], "open")
                self.assertEqual(result["attempts"], 2)
                self.assertEqual(len(result["observations"]), 2)
                self.assertEqual(
                    result["observations"][0]["result"],
                    "no-matching-response"
                )
                self.assertEqual(mock_sr1.call_count, 2)
                mock_send.assert_called_once()

    def test_unauthorised_port_not_transmitted(self):
        with patch("scanner.sr1") as mock_sr1:
            with patch("scanner.send") as mock_send:
                with self.assertRaises(ValueError):
                    self.scanner.scan_port(9999)
                mock_sr1.assert_not_called()
                mock_send.assert_not_called()
                
    def test_scan_all_four_ports(self):

        def fake_response(probe, **kwargs):

            port = probe[TCP].dport

            # Ports 22 and 80 respond with SYN-ACK
            if port in (22, 80):
                return IP(
                    src=probe[IP].dst,
                    dst=probe[IP].src
                ) / TCP(
                    sport=port,
                    dport=probe[TCP].sport,
                    flags="SA",
                    seq=5000,
                    ack=(probe[TCP].seq + 1) % (2**32)
                )

            # Port 443 responds with RST-ACK
            if port == 443:
                return IP(
                    src=probe[IP].dst,
                    dst=probe[IP].src
                ) / TCP(
                    sport=port,
                    dport=probe[TCP].sport,
                    flags="RA",
                    ack=(probe[TCP].seq + 1) % (2**32)
                )

            # Port 8080 produces no response
            return None

        with patch("scanner.sr1", side_effect=fake_response) as mock_sr1:
            with patch("scanner.send") as mock_send:

                report = self.scanner.scan_all_ports()

                self.assertEqual(
                    report["ports"],
                    [22, 80, 443, 8080]
                )

                states = {
                    item["port"]: item["state"]
                    for item in report["results"]
                }

                self.assertEqual(states, {
                    22: "open",
                    80: "open",
                    443: "closed",
                    8080: "filtered-or-no-response"
                })

                # 1 + 1 + 1 + 2 SYN attempts = 5
                self.assertEqual(report["syn_attempts"], 5)
                self.assertEqual(mock_sr1.call_count, 5)

                # Two open ports require two cleanup packets
                self.assertEqual(mock_send.call_count, 2)

                # Check report metadata
                self.assertEqual(report["mode"], "execute")
                self.assertIn("start_time_utc", report)
                self.assertIn("end_time_utc", report)
                
    def test_network_transmission_failure(self):
        # Simulate Scapy failing to transmit a SYN packet.
        with patch(
            "scanner.sr1",
            side_effect=OSError("Simulated network failure")
        ) as mock_sr1:
            with patch("scanner.send") as mock_send:
                with self.assertRaisesRegex(
                    OSError,
                    "Simulated network failure"
                ):
                    self.scanner.scan_port(22)
                # A failed transmission must not be treated
                # as a normal unanswered port.
                mock_sr1.assert_called_once()
                mock_send.assert_not_called()
                # No retry should follow this system error.
                self.assertEqual(
                    self.scanner.attempts_by_port[22],
                    1
                )
    def test_stability_verification_confirmed(self):

        def fake_syn_ack(probe, **kwargs):
            return IP(
                src=probe[IP].dst,
                dst=probe[IP].src
            ) / TCP(
                sport=probe[TCP].dport,
                dport=probe[TCP].sport,
                flags="SA",
                seq=5000,
                ack=(probe[TCP].seq + 1) % (2**32)
            )

        with patch("scanner.sr1", side_effect=fake_syn_ack) as mock_sr1:
            with patch("scanner.send") as mock_send:

                # First SYN: port is open
                initial = self.scanner.scan_port(22)

                # Second SYN: verify the first observation
                result = self.scanner.verify_open_port(22, initial)

                self.assertEqual(result["state"], "open")
                self.assertEqual(result["attempts"], 2)
                self.assertEqual(
                    result["verification"]["status"],
                    "confirmed"
                )
                self.assertEqual(len(result["observations"]), 2)

                # Exactly two SYNs and two RST cleanups
                self.assertEqual(mock_sr1.call_count, 2)
                self.assertEqual(mock_send.call_count, 2)


    def test_stability_verification_not_confirmed(self):

        reply_count = 0

        def fake_response(probe, **kwargs):
            nonlocal reply_count
            reply_count += 1

            # Second SYN receives no response
            if reply_count == 2:
                return None

            # First SYN receives SYN-ACK
            return IP(
                src=probe[IP].dst,
                dst=probe[IP].src
            ) / TCP(
                sport=probe[TCP].dport,
                dport=probe[TCP].sport,
                flags="SA",
                seq=6000,
                ack=(probe[TCP].seq + 1) % (2**32)
            )

        with patch("scanner.sr1", side_effect=fake_response) as mock_sr1:
            with patch("scanner.send") as mock_send:

                initial = self.scanner.scan_port(22)
                result = self.scanner.verify_open_port(22, initial)

                # Preserve the original open observation
                self.assertEqual(result["state"], "open")

                self.assertEqual(
                    result["verification"]["status"],
                    "not-confirmed"
                )
                self.assertEqual(
                    result["verification"]["second_observation"],
                    "no-matching-response"
                )

                self.assertEqual(result["attempts"], 2)
                self.assertEqual(mock_sr1.call_count, 2)

                # Only the first SYN-ACK required cleanup
                mock_send.assert_called_once()


    def test_stability_verification_attempt_limit(self):

        # Simulate two attempts already used
        self.scanner.attempts_by_port[22] = 2

        initial = {
            "port": 22,
            "state": "open",
            "attempts": 2,
            "observations": [
                {
                    "attempt": 1,
                    "result": "open",
                    "evidence": "syn-ack"
                }
            ]
        }

        with patch("scanner.sr1") as mock_sr1:
            with patch("scanner.send") as mock_send:

                result = self.scanner.verify_open_port(22, initial)

                self.assertEqual(
                    result["verification"]["status"],
                    "not-performed"
                )
                self.assertEqual(
                    result["verification"]["reason"],
                    "attempt-limit-reached"
                )

                # Absolutely no additional packets
                mock_sr1.assert_not_called()
                mock_send.assert_not_called()
                
    def test_scan_all_ports_with_verification(self):
        def fake_syn_ack(probe, **kwargs):
            # Simulate every authorised port returning SYN-ACK
            return IP(
                src=probe[IP].dst,
                dst=probe[IP].src
            ) / TCP(
                sport=probe[TCP].dport,
                dport=probe[TCP].sport,
                flags="SA",
                seq=5000,
                ack=(probe[TCP].seq + 1) % (2**32)
            )
        with patch("scanner.sr1", side_effect=fake_syn_ack) as mock_sr1:
            with patch("scanner.send") as mock_send:
                # Enable our new extension
                report = self.scanner.scan_all_ports(
                    verify_open=True
                )
                # Confirm the extension was enabled
                self.assertTrue(
                    report["stability_verification_enabled"]
                )
                # Four ports, two SYN attempts each
                self.assertEqual(report["syn_attempts"], 8)
                # Exactly eight SYN transmissions
                self.assertEqual(mock_sr1.call_count, 8)
                # Eight SYN-ACK responses require cleanup
                self.assertEqual(mock_send.call_count, 8)
                for result in report["results"]:
                    self.assertEqual(result["state"], "open")
                    self.assertEqual(result["attempts"], 2)
                    self.assertEqual(
                        result["verification"]["status"],
                        "confirmed"
                    )
                    self.assertEqual(
                        len(result["observations"]),
                        2
                    )
    
    def test_delayed_duplicate_response(self):
        first_reply = None
        call_count = 0
        def fake_response(probe, **kwargs):
            nonlocal first_reply, call_count
            call_count += 1
            # First probe: valid SYN-ACK for port 22
            if call_count == 1:
                first_reply = IP(
                    src=probe[IP].dst,
                    dst=probe[IP].src
                ) / TCP(
                    sport=probe[TCP].dport,
                    dport=probe[TCP].sport,
                    flags="SA",
                    seq=5000,
                    ack=(probe[TCP].seq + 1) % (2**32)
                )
                return first_reply
            # Second probe: delayed duplicate from port 22
            # It must NOT be accepted as port 80's response
            if call_count == 2:
                return first_reply.copy()
            # Third probe: genuine SYN-ACK for port 80
            return IP(
                src=probe[IP].dst,
                dst=probe[IP].src
            ) / TCP(
                sport=probe[TCP].dport,
                dport=probe[TCP].sport,
                flags="SA",
                seq=6000,
                ack=(probe[TCP].seq + 1) % (2**32)
            )
        with patch("scanner.sr1", side_effect=fake_response) as mock_sr1:
            with patch("scanner.send") as mock_send:
                # Scan port 22 successfully
                result22 = self.scanner.scan_port(22)
                # Port 80 first receives the old duplicate
                # and then a genuine response
                result80 = self.scanner.scan_port(80)
                self.assertEqual(result22["state"], "open")
                self.assertEqual(result22["attempts"], 1)
                self.assertEqual(result80["state"], "open")
                self.assertEqual(result80["attempts"], 2)
                # The duplicate must not be counted as valid
                self.assertEqual(
                    result80["observations"][0]["result"],
                    "no-matching-response"
                )
                # Three total SYN attempts
                self.assertEqual(mock_sr1.call_count, 3)

                # Only the two valid SYN-ACK responses
                # should trigger cleanup
                self.assertEqual(mock_send.call_count, 2)
                
    def test_repeatable_json_report(self):

        def fake_syn_ack(probe, **kwargs):
            return IP(
                src=probe[IP].dst,
                dst=probe[IP].src
            ) / TCP(
                sport=probe[TCP].dport,
                dport=probe[TCP].sport,
                flags="SA",
                seq=5000,
                ack=(probe[TCP].seq + 1) % (2**32)
            )

        reports = []

        with open(
            Path(__file__).resolve().parent / "fixtures" / "valid_scope.json",
            "r",
            encoding="utf-8"
        ) as file:
            scope = json.load(file)

        with patch(
            "scanner.sr1",
            side_effect=fake_syn_ack
        ) as mock_sr1:

            with patch("scanner.send") as mock_send:

                with patch.object(
                    TCPScanner,
                    "check_runtime_interface",
                    return_value="172.28.70.2"
                ):

                    with patch.object(
                        TCPScanner,
                        "wait_for_probe_slot"
                    ):

                        # Two independent scanner instances
                        for _ in range(2):

                            scanner = TCPScanner(scope)

                            report = scanner.scan_all_ports(
                                verify_open=False
                            )

                            # Timestamps naturally change.
                            report.pop("start_time_utc")
                            report.pop("end_time_utc")

                            reports.append(report)

                self.assertEqual(mock_sr1.call_count, 8)
                self.assertEqual(mock_send.call_count, 8)

        # Same observations must produce the same report data
        self.assertEqual(reports[0], reports[1])

        # Check required metadata
        self.assertEqual(
            reports[0]["scope_id"],
            "wqe7002-a1-standard-tcp-syn-scan-v1"
        )

        self.assertEqual(reports[0]["syn_attempts"], 4)
        self.assertEqual(reports[0]["ports"], [22, 80, 443, 8080])
                
     
                         
if __name__ == "__main__":
    unittest.main()
