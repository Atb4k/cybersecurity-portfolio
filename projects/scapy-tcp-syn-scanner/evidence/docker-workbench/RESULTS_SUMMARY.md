# Recorded Docker workbench results

These are original records from the provided WQE7002 assignment ZIP, not freshly executed scans.

**Authorised target** `172.28.70.10` | **source** `172.28.70.2` | **interface** `eth0` | **ports** 22, 80, 443, 8080.

- Primary Scapy JSON: all 4 allowed ports `open` after one SYN attempt per port.
- Independent Nmap XML: all the same 4 ports `open` (`syn-ack` evidence).
- Two baseline JSON runs: 4 SYN attempts in each; elapsed durations 0.585728 and 0.550317 seconds.
- Two verification JSON runs: 8 SYN attempts in each; durations 0.964346 and 0.907224 seconds. Each second observation confirmed an initially open result.
- Associated PCAP files support review of the observed packets.

**Interpretation:** agreement is only established for the four ports tested in these records. The classifier does not infer a version, a CVE, or successful exploitation from an open port.
