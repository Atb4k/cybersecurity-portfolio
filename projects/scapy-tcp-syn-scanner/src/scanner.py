from pathlib import Path
import tempfile
import os
import argparse
import json
import time
from scapy.all import IP, TCP, ICMP, IPerror, TCPerror, conf, get_if_list, sr1, send
import secrets
from datetime import datetime, timezone

class TCPScanner:

    def validate_scope(self, scope):
        
        # Verify the lecturer's authorised scope ID
        expected_scope_id = "wqe7002-a1-standard-tcp-syn-scan-v1"
        if scope.get("scope_id") != expected_scope_id:
            raise ValueError("Invalid or missing scope ID")
        
        
        # Verify the remaining lecturer scope fields
        required_fields = {
            "schema": "wqe7002-recon-scope-v1",
            "option": "tcp-syn-scan",
            "environment": "isolated-course-lab",
            "interface": "eth0",
            "topology": "wqe7002-course-lab Compose internal bridge",
            "capture_point": "workbench eth0; records the authorised scanner vantage point"
        }

        for field_name, expected_value in required_fields.items():

            if scope.get(field_name) != expected_value:
                raise ValueError(f"Invalid or missing {field_name}")


        # Check the authorised target
        if scope.get("target") != "172.28.70.10":
            raise ValueError("Unauthorised target IP")
            
        # Check the port list
        ports = scope.get("ports")
        if not isinstance(ports, list) or len(ports) == 0:
            raise ValueError("Invalid port list")
        approved_ports = (22, 80, 443, 8080)
        for port in ports:
            if type(port) is not int or port not in approved_ports:
                raise ValueError("Unauthorised port")
                
        # Reject duplicate ports
        if len(ports) != len(set(ports)):
            raise ValueError("Duplicate ports are not allowed")
            
        # Validate scanning rate
        rate = scope.get("maximum_rate_pps")
        if type(rate) is not int or not 1 <= rate <= 20:
            raise ValueError("Invalid scanning rate")
        # Validate maximum attempts
        attempts = scope.get("maximum_attempts")
        if type(attempts) is not int or not 1 <= attempts <= 2:
            raise ValueError("Invalid maximum attempts")
        # Validate timeout
        timeout = scope.get("timeout_seconds")
        if type(timeout) not in (int, float) or not 0 < timeout <= 1.5:
            raise ValueError("Invalid timeout")


    def __init__(self, scope):
        self.validate_scope(scope)
        self.scope_id = scope["scope_id"]
        self.interface = scope["interface"]
        # Store network information
        self.target = scope["target"]
        self.allowed_ports = tuple(scope["ports"])

        # Store authorised scanning limits
        self.maximum_rate = scope["maximum_rate_pps"]
        self.maximum_attempts = scope["maximum_attempts"]
        self.timeout = scope["timeout_seconds"]
        self.probe_interval = 1.0 / self.maximum_rate
        self.last_probe_time = None
        self.attempts_by_port = {
	    port: 0 for port in self.allowed_ports
	}
        self.used_source_ports = set()
        self.used_sequences = set()
        
    def build_syn_probe(self, port):
        # Reject unauthorised ports
        if type(port) is not int or port not in self.allowed_ports:
            raise ValueError("Port is not authorised")
        # Verify the interface and obtain our source IP
        source_ip = self.check_runtime_interface()
        # Choose a source port not previously used by this object
        while True:
            source_port = 49152 + secrets.randbelow(16384)
            if source_port not in self.used_source_ports:
                self.used_source_ports.add(source_port)
                break
        # Choose a new TCP sequence number
        while True:
            sequence = secrets.randbits(32)
            if sequence not in self.used_sequences:
                self.used_sequences.add(sequence)
                break
        packet = IP(
            src=source_ip,
            dst=self.target
        ) / TCP(
            sport=source_port,
            dport=port,
            flags="S",
            seq=sequence
        )
        return packet
    
    def wait_for_probe_slot(self):
        now = time.monotonic()
        if self.last_probe_time is not None:
            elapsed = now - self.last_probe_time
            remaining = self.probe_interval - elapsed
            if remaining > 0:
                time.sleep(remaining)
        self.last_probe_time = time.monotonic()
        
    def reserve_probe_attempt(self, port):
        # Ensure the port is authorised
        if type(port) is not int or port not in self.allowed_ports:
            raise ValueError("Port is not authorised")
        # Check how many attempts have already been reserved
        attempts_used = self.attempts_by_port[port]
        if attempts_used >= self.maximum_attempts:
            raise RuntimeError(
                f"Maximum attempts reached for port {port}"
            )
        # Reserve one more attempt
        self.attempts_by_port[port] = attempts_used + 1
        return self.attempts_by_port[port]
        
    def prepare_probe_attempt(self, port):
        # Construct an authorised SYN packet
        packet = self.build_syn_probe(port)
        # Reserve one attempt for this port
        attempt_number = self.reserve_probe_attempt(port)
        # Wait until the next permitted probe opportunity
        self.wait_for_probe_slot()
        return attempt_number, packet

    def classify_response(self, probe, response):
        # Check whether a valid TCP/IP response exists
        if response is None or IP not in response:
            return None
        # Handle ICMP errors using our new method
        if ICMP in response:
            return self.classify_icmp_response(probe, response)
        # Otherwise, check whether it is a TCP response
        if TCP not in response:
            return None
        # Check whether the reply matches our original SYN probe
        if (
            response[IP].src != probe[IP].dst
            or response[IP].dst != probe[IP].src
            or response[TCP].sport != probe[TCP].dport
            or response[TCP].dport != probe[TCP].sport
        ):
            return None
        # Verify the acknowledgment number
        if (
            response[TCP].flags.A
            and response[TCP].ack != (probe[TCP].seq + 1) % (2**32)
        ):
            return None
        # Extract the TCP flags
        flags = response[TCP].flags

        # Reject contradictory SYN and RST combinations
        if flags.S and flags.R:
            return None

        # SYN-ACK indicates an open port
        if flags.S and flags.A:
            return "open"

        # RST indicates a closed port
        if flags.R:
            return "closed"
        return None
        
    def build_rst_cleanup(self, probe, response):

        # Only build cleanup for a matching SYN-ACK
        if self.classify_response(probe, response) != "open":
            return None

        # Construct a TCP reset packet
        rst_packet = IP(
            src=probe[IP].src,
            dst=probe[IP].dst
        ) / TCP(
            sport=probe[TCP].sport,
            dport=probe[TCP].dport,
            flags="RA",
            seq=response[TCP].ack,
            ack=(response[TCP].seq + 1) % (2**32)
        )

        return rst_packet
        
    def classify_icmp_response(self, probe, response):
        if response is None or IP not in response or ICMP not in response:
            return None
        icmp = response[ICMP]
        # Check relevant ICMP unreachable messages
        if icmp.type != 3 or icmp.code not in (1, 2, 3, 9, 10, 13):
            return None
        # Check that the error was addressed to our scanner
        if response[IP].dst != probe[IP].src:
            return None
        quoted = icmp.payload
        # Extract the original packet quoted inside ICMP
        if IPerror in quoted and TCPerror in quoted:
            quoted_ip = quoted[IPerror]
            quoted_tcp = quoted[TCPerror]
        elif IP in quoted and TCP in quoted:
            quoted_ip = quoted[IP]
            quoted_tcp = quoted[TCP]
        else:
            return None
        # Verify that the quoted packet matches our SYN
        if (
            quoted_ip.src != probe[IP].src
            or quoted_ip.dst != probe[IP].dst
            or quoted_tcp.sport != probe[TCP].sport
            or quoted_tcp.dport != probe[TCP].dport
            or quoted_tcp.seq != probe[TCP].seq
        ):
            return None
        return "filtered-or-no-response"
        
    def scan_port(self, port):
        observations = []
        for _ in range(self.maximum_attempts):
            # Prepare a SYN using our existing safety controls
            attempt_number, probe = self.prepare_probe_attempt(port)
            # Transmit the SYN and wait for a response
            response = sr1(
                probe,
                timeout=self.timeout,
                retry=0,
                verbose=False
            )
            # Classify only a response matching our original probe
            result = self.classify_response(probe, response)
            if result is not None:
                if ICMP in response:
                    evidence = "icmp-unreachable"
                elif result == "open":
                    evidence = "syn-ack"
                else:
                    evidence = "rst"
                observations.append({
                    "attempt": attempt_number,
                    "result": result,
                    "evidence": evidence
                })
                # Close a matching SYN-ACK exchange
                if result == "open":
                    rst = self.build_rst_cleanup(probe, response)
                    if rst is None:
                        raise RuntimeError(
                            "Unable to construct RST cleanup"
                        )
                    self.wait_for_probe_slot()
                    send(rst, verbose=False)
                return {
                    "port": port,
                    "state": result,
                    "attempts": attempt_number,
                    "observations": observations
                }
            # Timeout or unrelated response: no decisive evidence
            observations.append({
                "attempt": attempt_number,
                "result": "no-matching-response",
                "evidence": (
                    "timeout" if response is None
                    else "unrelated-or-unclassified-response"
                )
            })
        return {
            "port": port,
            "state": "filtered-or-no-response",
            "attempts": self.attempts_by_port[port],
            "observations": observations
        }
    def verify_open_port(self, port, initial_result):
        # Confirm only an authorised port
        if type(port) is not int or port not in self.allowed_ports:
            raise ValueError("Port is not authorised")
        # Verification applies only to an initially open port
        if (
            initial_result["port"] != port
            or initial_result["state"] != "open"
        ):
            raise ValueError("Verification requires a matching open result")
        # Never exceed the lecturer's attempt limit
        if self.attempts_by_port[port] >= self.maximum_attempts:
            initial_result["verification"] = {
                "status": "not-performed",
                "reason": "attempt-limit-reached"
            }
            return initial_result
        # Prepare one additional authorised SYN
        attempt_number, probe = self.prepare_probe_attempt(port)
        # Send it and collect the response
        response = sr1(
            probe,
            timeout=self.timeout,
            retry=0,
            verbose=False
        )
        second_state = self.classify_response(probe, response)
        # Clean up a matching SYN-ACK
        if second_state == "open":
            rst = self.build_rst_cleanup(probe, response)
            if rst is None:
                raise RuntimeError("Unable to construct RST cleanup")
            self.wait_for_probe_slot()
            send(rst, verbose=False)
        # Record the independent second observation
        initial_result["attempts"] = attempt_number
        initial_result["observations"].append({
            "attempt": attempt_number,
            "result": second_state or "no-matching-response",
            "evidence": "stability-check"
        })
        initial_result["verification"] = {
            "status": (
                "confirmed" if second_state == "open"
                else "not-confirmed"
            ),
            "second_observation": (
                second_state or "no-matching-response"
            )
        }
        return initial_result
    
    def scan_all_ports(self,verify_open=False):
        # Verify the authorised network interface
        source_ip = self.check_runtime_interface()
        # Record the UTC start time
        start_time = datetime.now(timezone.utc)
        results = []
        # Scan only the ports listed in the authorised scope
        for port in self.allowed_ports:
            # Run the normal TCP SYN scan
            port_result = self.scan_port(port)
            # Optionally verify an initially open port
            if verify_open and port_result["state"] == "open":
                port_result = self.verify_open_port(
                    port,
                    port_result
                )
            # Store the final result for this port
            results.append(port_result)
        # Record the UTC finish time
        end_time = datetime.now(timezone.utc)
        # Count the SYN attempts made by our scanner
        total_attempts = sum(self.attempts_by_port.values())
        # Build the final JSON report
        report = {
            "tool": "WQE7002 Scapy TCP SYN Scanner",
            "tool_version": "1.0.0",
            "mode": "execute",
            "stability_verification_enabled": verify_open,
            "scope_id": self.scope_id,
            "option": "tcp-syn-scan",
            "start_time_utc": start_time.isoformat(),
            "end_time_utc": end_time.isoformat(),
            "target": self.target,
            "interface": self.interface,
            "source_ip": source_ip,
            "ports": list(self.allowed_ports),
            "maximum_rate_pps": self.maximum_rate,
            "maximum_attempts": self.maximum_attempts,
            "timeout_seconds": self.timeout,
            "syn_attempts": total_attempts,
            "results": results
        }
        return report
        
    def show_settings(self):
        print("Target:", self.target)
        print("Allowed ports:", self.allowed_ports)
        print("Maximum rate:", self.maximum_rate)
        print("Maximum attempts:", self.maximum_attempts)
        print("Timeout:", self.timeout)
        
    def check_runtime_interface(self):

        # Get available network interfaces
        interfaces = get_if_list()

        if self.interface not in interfaces:
            raise RuntimeError("Authorised interface not found")

        # Check the route Scapy would use
        outgoing_interface, source_ip, gateway = conf.route.route(self.target)

        if outgoing_interface != self.interface:
            raise RuntimeError("Target route uses an unauthorised interface")

        return source_ip

    
    def create_dry_run_report(self):
        report = {
            "tool": "WQE7002 Scapy TCP SYN Scanner",
            "tool_version": "1.0.0",
            "mode": "dry-run",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "scope_id": self.scope_id,
            "option": "tcp-syn-scan",
            "target": self.target,
            "interface": self.interface,
            "ports": list(self.allowed_ports),
            "maximum_rate_pps": self.maximum_rate,
            "minimum_probe_interval_seconds": self.probe_interval,
            "maximum_attempts": self.maximum_attempts,
            "timeout_seconds": self.timeout,
            "packets_sent": 0,
            "scan_plan": self.create_scan_plan()
        }
        return report

    def create_scan_plan(self):
        plan = []
        for port in self.allowed_ports:
            plan.append({
                "target": self.target,
                "port": port,
                "packet": f"TCP SYN to {self.target}:{port} (planned only)",
                "maximum_attempts": self.maximum_attempts,
                "timeout": self.timeout
            })
        return plan

def validate_output_destination(output):

    output_path = Path(output)

    # Never overwrite an existing evidence file
    if output_path.exists() or output_path.is_symlink():
        raise ValueError(
            "Output file already exists; choose a new filename"
        )

    # Check that the destination directory exists
    parent = output_path.parent

    if not parent.is_dir():
        raise ValueError("Output directory does not exist")

    # Check that the directory allows file creation
    try:
        with tempfile.TemporaryFile(dir=parent):
            pass
    except OSError as error:
        raise ValueError(
            f"Output directory is not writable: {error}"
        )

def save_json_report(report, output):

    destination = Path(output)
    temporary_path = None

    try:
        # Create a temporary file in the same directory
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=".scanner-",
            suffix=".tmp",
            delete=False
        ) as temporary_file:

            temporary_path = Path(temporary_file.name)

            # Write the complete JSON report
            json.dump(report, temporary_file, indent=2)
            temporary_file.write("\n")

            # Flush the data before publishing the file
            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        # Publish the completed file without overwriting
        # an existing destination
        os.link(temporary_path, destination)

    finally:
        # Remove the temporary filename
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

def main():
    parser = argparse.ArgumentParser(
        description="WQE7002 TCP SYN Scanner"
    )
    parser.add_argument(
        "--scope",
        required=True,
        help="Path to the authorised scope JSON"
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to the output JSON file"
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute an authorised TCP SYN scan"
    )
    parser.add_argument(
        "--verify-open",
        action="store_true",
        help="Verify initially open ports with one additional SYN"
    )
    args = parser.parse_args()
    # Stability verification is only available during live execution
    if args.verify_open and not args.execute:
        parser.error("--verify-open requires --execute")
    
    # Load the lecturer's trusted scope
    trusted_scope_path = "/scopes/assignment-01-tcp-syn-scan.json"
    try:
        with open(trusted_scope_path, "r", encoding="utf-8") as file:
            trusted_scope = json.load(file)
    except (OSError, json.JSONDecodeError) as error:
        parser.error(f"Cannot load lecturer's trusted scope: {error}")
    # Load the scope requested through the CLI
    try:
        with open(args.scope, "r", encoding="utf-8") as file:
            scope = json.load(file)
    except (OSError, json.JSONDecodeError) as error:
        parser.error(f"Cannot load requested scope: {error}")
        
        
    # Compare the supplied scope with the trusted scope
    if scope != trusted_scope:
        parser.error("Scope does not match the lecturer's authorised scope")
    # Create our scanner object and validate its settings
    # Create the scanner and validate its settings and interface
    try:
        scanner = TCPScanner(scope)
        source_ip = scanner.check_runtime_interface()
    except (ValueError, TypeError, KeyError, RuntimeError, OSError) as error:
        parser.error(f"Scanner validation failed: {error}")
    print("Authorised interface verified:", scanner.interface)
    print("Selected source IP:", source_ip)
    print("Minimum probe interval:", scanner.probe_interval, "seconds")
    
    # Validate output destination before any live probes
    try:
        validate_output_destination(args.output)
    except (OSError, ValueError) as error:
        parser.error(f"Invalid output destination: {error}")
    
    # Only transmit packets when --execute is explicitly supplied
    if args.execute:
        print("Starting authorised TCP SYN scan...")
        try:
            report = scanner.scan_all_ports(
            	verify_open=args.verify_open
            )
        except (OSError, RuntimeError, ValueError) as error:
            parser.error(f"Live scan failed: {error}")
    else:
        print("DRY RUN: No packets will be transmitted")
        report = scanner.create_dry_run_report()

    # Safely save the completed JSON report
    try:
        save_json_report(report, args.output)

    except (OSError, TypeError, ValueError) as error:
        parser.error(f"Cannot save JSON report: {error}")

    print("Scope file:", args.scope)
    print("Mode:", report["mode"])
    print("Report saved:", args.output)

    if args.execute:
        print("SYN attempts:", report["syn_attempts"])

        for result in report["results"]:
            print(
                f"Port {result['port']}: "
                f"{result['state']} "
                f"({result['attempts']} attempt(s))"
            )
    else:
        print("Packets sent:", report["packets_sent"])
    
if __name__ == "__main__":
    main()
