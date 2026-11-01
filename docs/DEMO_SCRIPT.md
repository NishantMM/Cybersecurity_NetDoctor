
| Time | Show | Say |
|---|---|---|
| 0:00 to 0:30 | Title + a Wireshark capture scrolling | "Small offices have no network engineer. Reading a capture takes deep protocol knowledge, and an outage looks just like an attack." |
| 0:30 to 1:00 | Architecture diagram from README | "NetDoctor reads a capture with our own parser and our own detection logic, no Scapy or Wireshark, and says what's wrong, why, and how to fix it." |
| 1:00 to 1:40 | `01_normal.pcap` then `02_outage_faults.pcap` | "Healthy traffic: silence, no false alarm. Now an outage: retransmissions, DNS timeouts, MTU. Verdict: FAULT ONLY, no attack." |
| 1:40 to 2:40 | `03_arp_spoofing`, `04_port_scan`, `05_dns_hijack`, `06_rogue_dhcp` (30 s each, HTML report) | Read the plain-language box, point at the evidence packets and the timeline. |
| 2:40 to 3:20 | `08_mixed_incident.pcap` | "The key problem: outage vs attack. Here both happen. NetDoctor separates them and links the retransmissions to the ARP attack as a side effect." |
| 3:20 to 3:50 | `malformed.pcap`, then run `python -m unittest` | "Hostile input: corrupt files give a warning, never a crash; fuzz tests; output is HTML-escaped; web upload is size-limited." |
| 3:50 to 4:15 | README + limitations | "Setup is one command, no dependencies. Limits: IPv4 only. Next: IPv6, live capture." |

