# Metasploitable 2 personal lab — evidence and limitations

This is a **separate personal host-only lab** using Kali Linux and a
deliberately vulnerable Metasploitable 2 VM. It must not be confused
with the course-issued Docker scan scope and scanner implementation.

## Observations from supplied screenshots

- The virtual lab used `192.168.56.0/24`; Metasploitable was `192.168.56.106`.
- A screenshot shows a Python script reading a saved scan result JSON file.
- The saved result summary shows **100 TCP ports**, **100 SYN attempts**,
  **18 open**, **82 closed**, and **0 filtered/no-response**.
- A separate Nmap top-100 screenshot corroborates the **18-open count**.
- A screenshot shows personal scanner-related source/scope files.

## Not supplied

- An original screenshot showing the custom scanner's command executing.
- The exact personal Metasploitable scanner source code.
- The raw saved Metasploitable JSON and PCAP (if any).

Therefore, the saved-results screenshot is labelled as a **result summary**,
not as a live scanner-command screenshot. This repository includes the
course-authorised Docker implementation, but does not claim it is the exact
variant used for this separate VM experiment.

## Screenshots

- [VM network](../evidence/screenshots/metasploitable-network.png)
- [Saved JSON summary](../evidence/screenshots/metasploitable-results.png)
- [Nmap comparison](../evidence/screenshots/metasploitable-nmap.png)
- [Scanner-related files](../evidence/screenshots/metasploitable-scanner-files.png)

**Ethics:** All testing must remain within owned or explicitly authorised
isolated laboratory systems.
