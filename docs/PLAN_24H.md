# 24-hour plan (start Sat 31/10 9:00 PM, hard deadline Sun 01/11 9:00 PM)

Submit by **7:30 PM Sunday** at the latest. The form is the only way in, and late commits are ignored.
Sleep 5-6 hours in one block so the second half of the day is not wasted.

## Roles (1 to 3 people; solo? do them in this order)
* **A, Engine:** pcap reader, dissector, detectors. **B, Samples + tests + security.** **C, Report/UI + README + video.**
* If solo: engine, then samples, then report, then README, then video.

## Timeline
| Time | Goal |
|---|---|
| Sat 9 PM to 11 PM | Run NetDoctor as is on all samples. Read every file once so you can explain it. Create the public GitHub repo, push. |
| Sat 11 PM to 3 AM | **Your own improvements** (this is the 30% + 20% novelty part): see "make it yours" below. |
| 3 AM to 9 AM | Sleep. |
| Sun 9 AM to 1 PM | Finish improvements, add 1-2 more sample captures, tests green, security pass. |
| 1 PM to 3 PM | Polish HTML report, README screenshots, tune thresholds on your own captures. |
| 3 PM to 5:30 PM | Record the demo (see DEMO_SCRIPT.md). Retake as needed. |
| 5:30 PM to 6:30 PM | Fresh-clone test: clone into a new folder, follow README exactly. |
| 6:30 PM to 7:30 PM | Submit via Google Form (team leader only). Check repo is public and video link works. |
| 7:30 PM to 9 PM | Buffer. Do **not** push risky changes. |

## Make it yours (judges score "how much of the detection logic is the team's own")
You must be able to explain every line. Pick 2 to 4:
1. Capture your own lab traffic (VM + `arpspoof`/`nmap` on a network you own) and add it to `samples/`.
2. Add a detector: SYN flood, DNS tunnelling (long/entropy-heavy names), ICMP flood, IPv6 NDP spoofing, TCP window-zero stalls.
3. Add a **confidence breakdown** per finding (list the rules that fired).
4. Per-host health score in the HTML report.
5. Tune thresholds on real captures and write the results in the README (shows evaluation).
6. Add a tiny "explain like I'm new" glossary box to each finding.
