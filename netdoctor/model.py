from __future__ import annotations
from dataclasses import dataclass, field

MAX_EVIDENCE = 40  # keep reports small and bounded


@dataclass
class Finding:
    code: str                 # machine id, e.g. "arp_spoofing"
    kind: str                 # "fault" | "attack" | "info"
    title: str
    severity: str             # "low" | "medium" | "high"
    confidence: float         # 0..1
    summary: str              # plain-language explanation
    cause: str                # likely cause
    fix: str                  # suggested next step
    packets: list = field(default_factory=list)   # packet numbers (evidence)
    hosts: set = field(default_factory=set)       # IPs involved
    t_start: float = 0.0
    t_end: float = 0.0
    details: dict = field(default_factory=dict)

    def finalize(self):
        self.packets = sorted(set(self.packets))
        self.details["evidence_total"] = len(self.packets)
        self.packets = self.packets[:MAX_EVIDENCE]
        return self

    def to_dict(self):
        return {
            "code": self.code, "kind": self.kind, "title": self.title,
            "severity": self.severity, "confidence": round(self.confidence, 2),
            "summary": self.summary, "cause": self.cause, "fix": self.fix,
            "evidence_packets": self.packets, "hosts": sorted(self.hosts),
            "t_start": self.t_start, "t_end": self.t_end, "details": self.details,
        }
