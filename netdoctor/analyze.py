from __future__ import annotations
from collections import Counter

from .detectors import DETECTORS, Context
from .dissect import dissect
from .pcap import read_capture

SEV = {"high": 0, "medium": 1, "low": 2}


def analyze_file(path, max_packets=None):
    kw = {"max_packets": max_packets} if max_packets else {}
    raws, warnings = read_capture(path, **kw)
    pk = [dissect(r) for r in raws]
    return analyze_packets(pk, warnings)


def analyze_packets(pk, warnings=()):
    ctx = Context(pk)
    findings = []
    if pk:
        for det in DETECTORS:          # order matters: scan detector runs first
            try:
                findings += det(pk, ctx)
            except Exception as e:     # one bad rule must never kill the report
                warnings = list(warnings) + [f"detector {det.__name__} failed: {type(e).__name__}"]
    _correlate(findings)
    findings.sort(key=lambda f: (f.kind != "attack", SEV[f.severity], -f.confidence))
    attacks = [f for f in findings if f.kind == "attack"]
    faults = [f for f in findings if f.kind == "fault"]
    if attacks and faults and any(f.details.get("caused_by") for f in faults):
        verdict = "ATTACK: malicious activity found, and some of the faults are probably its side effects"
    elif attacks and faults:
        verdict = "ATTACK AND FAULTS: malicious activity found, plus separate ordinary network faults"
    elif attacks:
        verdict = "ATTACK: malicious activity found"
    elif faults:
        verdict = "FAULT ONLY: ordinary network problems, no sign of an attack"
    else:
        verdict = "HEALTHY: nothing suspicious found"
    protos = Counter()
    for p in pk:
        protos["ARP" if p.arp_op else "TCP" if p.is_tcp else "UDP" if p.is_udp
               else "ICMP" if p.proto == 1 else "other"] += 1
    return {
        "verdict": verdict, "findings": findings, "warnings": list(warnings), "packets": pk,
        "stats": {"packets": len(pk), "duration": round(pk[-1].ts - pk[0].ts, 3) if pk else 0,
                  "protocols": dict(protos), "attacks": len(attacks), "faults": len(faults)},
    }


def _correlate(findings):
    """A fault that involves hosts named in an attack may be its side effect."""
    attacks = [f for f in findings if f.kind == "attack"]
    for f in findings:
        if f.kind != "fault":
            continue
        for a in attacks:
            if f.hosts & a.hosts and a.code in ("arp_spoofing", "dns_hijack", "rogue_dhcp"):
                f.details["caused_by"] = a.code
                f.summary += (f" Note: these hosts also appear in the attack finding '{a.title}', "
                              f"so this problem may be a side effect of the attack. Deal with the attack first.")
                break
