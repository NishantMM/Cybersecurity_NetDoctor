"""Own protocol dissector: Ethernet, ARP, IPv4, TCP, UDP, ICMP, DNS, DHCP.
Never raises on malformed data: a bad layer simply stays None."""
from __future__ import annotations
import ipaddress
import struct
from dataclasses import dataclass, field
from typing import Optional

SYN, ACK, RST, FIN = 0x02, 0x10, 0x04, 0x01


def mac_str(b):
    return ":".join(f"{x:02x}" for x in b)


def ip_str(b):
    return str(ipaddress.IPv4Address(bytes(b)))


@dataclass
class Pkt:
    no: int
    ts: float
    length: int
    eth_src: str = ""
    eth_dst: str = ""
    # ARP
    arp_op: int = 0
    arp_sha: str = ""
    arp_spa: str = ""
    arp_tha: str = ""
    arp_tpa: str = ""
    # IP
    src: str = ""
    dst: str = ""
    proto: int = 0
    ip_len: int = 0
    df: bool = False
    # TCP / UDP
    sport: int = 0
    dport: int = 0
    seq: int = 0
    ackn: int = 0
    flags: int = 0
    payload: int = 0
    mss: int = 0
    # ICMP
    icmp_type: int = -1
    icmp_code: int = 0
    icmp_mtu: int = 0
    # DNS
    dns: Optional[dict] = None
    # DHCP
    dhcp: Optional[dict] = None

    @property
    def is_tcp(self):
        return self.proto == 6

    @property
    def is_udp(self):
        return self.proto == 17


def dissect(raw):
    p = Pkt(raw.no, raw.ts, raw.orig_len)
    d = raw.data
    try:
        if raw.linktype == 113:           # Linux cooked
            if len(d) < 16:
                return p
            et, off = struct.unpack_from(">H", d, 14)[0], 16
        else:
            if len(d) < 14:
                return p
            p.eth_dst, p.eth_src = mac_str(d[0:6]), mac_str(d[6:12])
            et, off = struct.unpack_from(">H", d, 12)[0], 14
            while et in (0x8100, 0x88A8) and off + 4 <= len(d):   # VLAN tags
                et = struct.unpack_from(">H", d, off + 2)[0]
                off += 4
        if et == 0x0806:
            _arp(p, d, off)
        elif et == 0x0800:
            _ipv4(p, d, off)
    except (struct.error, ValueError, IndexError):
        pass
    return p


def _arp(p, d, off):
    if len(d) < off + 28:
        return
    htype, ptype, hl, pl, op = struct.unpack_from(">HHBBH", d, off)
    if htype != 1 or ptype != 0x0800 or hl != 6 or pl != 4:
        return
    p.arp_op = op
    p.arp_sha, p.arp_spa = mac_str(d[off + 8:off + 14]), ip_str(d[off + 14:off + 18])
    p.arp_tha, p.arp_tpa = mac_str(d[off + 18:off + 24]), ip_str(d[off + 24:off + 28])


def _ipv4(p, d, off):
    if len(d) < off + 20 or d[off] >> 4 != 4:
        return
    ihl = (d[off] & 0x0F) * 4
    tot = struct.unpack_from(">H", d, off + 2)[0]
    frag = struct.unpack_from(">H", d, off + 6)[0]
    p.proto, p.df = d[off + 9], bool(frag & 0x4000)
    p.src, p.dst = ip_str(d[off + 12:off + 16]), ip_str(d[off + 16:off + 20])
    if ihl < 20 or tot < ihl:
        return
    p.ip_len = tot
    end = min(off + tot, len(d))
    l4 = off + ihl
    if frag & 0x1FFF:                      # non-first fragment: no L4 header
        return
    if p.proto == 6 and end >= l4 + 20:
        _tcp(p, d, l4, end, tot - ihl)
    elif p.proto == 17 and end >= l4 + 8:
        p.sport, p.dport = struct.unpack_from(">HH", d, l4)
        p.payload = max(0, struct.unpack_from(">H", d, l4 + 4)[0] - 8)
        body = d[l4 + 8:end]
        if 53 in (p.sport, p.dport):
            p.dns = _dns(body)
        elif {p.sport, p.dport} & {67, 68}:
            p.dhcp = _dhcp(body)
    elif p.proto == 1 and end >= l4 + 8:
        p.icmp_type, p.icmp_code = d[l4], d[l4 + 1]
        p.icmp_mtu = struct.unpack_from(">H", d, l4 + 6)[0]


def _tcp(p, d, l4, end, seg_len):
    p.sport, p.dport, p.seq, p.ackn = struct.unpack_from(">HHII", d, l4)
    hl = (d[l4 + 12] >> 4) * 4
    p.flags = d[l4 + 13]
    if hl < 20:
        return
    p.payload = max(0, seg_len - hl)
    o = l4 + 20
    while o + 1 < min(l4 + hl, end):          # options (bounded)
        kind = d[o]
        if kind == 0:
            break
        if kind == 1:
            o += 1
            continue
        ln = d[o + 1]
        if ln < 2:
            break
        if kind == 2 and ln == 4 and o + 4 <= end:
            p.mss = struct.unpack_from(">H", d, o + 2)[0]
        o += ln


def _name(d, off, jumps=0):
    labels, total, ptr_end = [], 0, None
    while True:
        if off >= len(d) or jumps > 10:
            raise ValueError("bad dns name")
        ln = d[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(d):
                raise ValueError("bad pointer")
            ptr = ((ln & 0x3F) << 8) | d[off + 1]
            if ptr_end is None:
                ptr_end = off + 2
            off, jumps = ptr, jumps + 1
            continue
        if ln > 63 or off + 1 + ln > len(d):
            raise ValueError("bad label")
        labels.append(d[off + 1:off + 1 + ln].decode("ascii", "replace"))
        total += ln + 1
        if total > 255:
            raise ValueError("name too long")
        off += 1 + ln
    return ".".join(labels).lower(), (ptr_end if ptr_end is not None else off)


def _dns(d):
    try:
        if len(d) < 12:
            return None
        tid, fl, qd, an = struct.unpack_from(">HHHH", d, 0)
        qd, an = min(qd, 8), min(an, 32)
        off, qname, qtype = 12, "", 0
        for i in range(qd):
            n, off = _name(d, off)
            if i == 0:
                qname, qtype = n, struct.unpack_from(">H", d, off)[0]
            off += 4
        answers = []
        for _ in range(an):
            _, off = _name(d, off)
            rtype, _, _, rdl = struct.unpack_from(">HHIH", d, off)
            off += 10
            if rtype == 1 and rdl == 4 and off + 4 <= len(d):
                answers.append(ip_str(d[off:off + 4]))
            off += rdl
        return {"id": tid, "qr": bool(fl & 0x8000), "rcode": fl & 0xF,
                "qname": qname, "qtype": qtype, "answers": tuple(sorted(answers))}
    except (struct.error, ValueError, IndexError):
        return None


def _dhcp(d):
    try:
        if len(d) < 240 or d[236:240] != b"\x63\x82\x53\x63":
            return None
        info = {"op": d[0], "xid": struct.unpack_from(">I", d, 4)[0],
                "yiaddr": ip_str(d[16:20]), "chaddr": mac_str(d[28:34]),
                "type": 0, "server_id": "", "router": "", "dns": ""}
        o = 240
        while o < len(d):
            code = d[o]
            if code == 255:
                break
            if code == 0:
                o += 1
                continue
            ln = d[o + 1]
            v = d[o + 2:o + 2 + ln]
            if code == 53 and ln == 1:
                info["type"] = v[0]
            elif code == 54 and ln == 4:
                info["server_id"] = ip_str(v)
            elif code == 3 and ln >= 4:
                info["router"] = ip_str(v[:4])
            elif code == 6 and ln >= 4:
                info["dns"] = ip_str(v[:4])
            o += 2 + ln
        return info
    except (struct.error, ValueError, IndexError):
        return None
