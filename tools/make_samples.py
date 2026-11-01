"""Generate the synthetic sample captures in ../samples (no network access, no real traffic).
Run:  python tools/make_samples.py
"""
import os
import random
import socket
import struct

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples")
random.seed(7)


def mac(s): return bytes(int(x, 16) for x in s.split(":"))
def ip(s): return socket.inet_aton(s)


def csum(b):
    if len(b) % 2:
        b += b"\0"
    t = sum(struct.unpack(f">{len(b) // 2}H", b))
    while t >> 16:
        t = (t & 0xFFFF) + (t >> 16)
    return ~t & 0xFFFF


def eth(dst, src, et, payload):
    return mac(dst) + mac(src) + struct.pack(">H", et) + payload


def ipv4(src, dst, proto, payload, df=True, ident=1):
    h = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000 if df else 0, 64, proto, 0, ip(src), ip(dst))
    h = h[:10] + struct.pack(">H", csum(h)) + h[12:]
    return h + payload


def tcp(src, dst, sport, dport, seq, ack, flags, data=b"", mss=None):
    opts = struct.pack(">BBH", 2, 4, mss) if mss else b""
    hl = (20 + len(opts)) // 4
    h = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, hl << 4, flags, 65535, 0, 0) + opts
    pseudo = ip(src) + ip(dst) + struct.pack(">BBH", 0, 6, len(h) + len(data))
    c = csum(pseudo + h + data)
    return h[:16] + struct.pack(">H", c) + h[18:] + data


def udp(src, dst, sport, dport, data):
    h = struct.pack(">HHHH", sport, dport, 8 + len(data), 0)
    pseudo = ip(src) + ip(dst) + struct.pack(">BBH", 0, 17, len(h) + len(data))
    return h[:6] + struct.pack(">H", csum(pseudo + h + data) or 0xFFFF) + data


def arp(op, sha, spa, tha, tpa):
    return struct.pack(">HHBBH", 1, 0x0800, 6, 4, op) + mac(sha) + ip(spa) + mac(tha) + ip(tpa)


def dns_name(n):
    return b"".join(bytes([len(l)]) + l.encode() for l in n.split(".")) + b"\0"


def dns_q(tid, name):
    return struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack(">HH", 1, 1)


def dns_r(tid, name, answers, rcode=0):
    h = struct.pack(">HHHHHH", tid, 0x8180 | rcode, 1, len(answers), 0, 0) + dns_name(name) + struct.pack(">HH", 1, 1)
    for a in answers:
        h += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + ip(a)
    return h


def dhcp(op, xid, client_mac, yiaddr, mtype, server=None, router=None, dns=None):
    b = struct.pack(">BBBBIHHIIII", op, 1, 6, 0, xid, 0, 0x8000, 0, struct.unpack(">I", ip(yiaddr))[0], 0, 0)
    b += mac(client_mac) + b"\0" * 10 + b"\0" * 192 + b"\x63\x82\x53\x63"
    b += bytes([53, 1, mtype])
    if server: b += bytes([54, 4]) + ip(server)
    if router: b += bytes([3, 4]) + ip(router)
    if dns: b += bytes([6, 4]) + ip(dns)
    return b + b"\xff"


class Cap:
    def __init__(self): self.pk = []
    def add(self, t, frame): self.pk.append((t, frame))
    def save(self, name):
        self.pk.sort(key=lambda x: x[0])
        t0 = int(self.pk[0][0])
        with open(os.path.join(OUT, name), "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for t, fr in self.pk:
                f.write(struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(fr), len(fr)) + fr)
        print("wrote", name, len(self.pk), "packets")


T = 1_800_000_000.0
GW, GWM = "192.168.1.1", "aa:aa:aa:00:00:01"
H = {"pc1": ("192.168.1.10", "02:00:00:00:00:10"), "pc2": ("192.168.1.11", "02:00:00:00:00:11"),
     "pc3": ("192.168.1.12", "02:00:00:00:00:12"), "srv": ("192.168.1.50", "02:00:00:00:00:50")}
WEB = "93.184.216.34"


def conn(c, t, cip, cmac, sip, smac, sport_c, dport, rtt=0.02, n_data=3, payload=b"x" * 500):
    seq, sseq = 1000, 5000
    f = lambda s, d, sm, dm, seg: eth(dm, sm, 0x0800, ipv4(s, d, 6, seg))
    c.add(t, f(cip, sip, cmac, smac, tcp(cip, sip, sport_c, dport, seq, 0, 0x02, mss=1460)))
    c.add(t + rtt, f(sip, cip, smac, cmac, tcp(sip, cip, dport, sport_c, sseq, seq + 1, 0x12, mss=1460)))
    c.add(t + rtt * 2, f(cip, sip, cmac, smac, tcp(cip, sip, sport_c, dport, seq + 1, sseq + 1, 0x10)))
    seq += 1
    for i in range(n_data):
        tt = t + rtt * (3 + i * 2)
        c.add(tt, f(cip, sip, cmac, smac, tcp(cip, sip, sport_c, dport, seq, sseq + 1, 0x18, payload)))
        seq += len(payload)
        c.add(tt + rtt, f(sip, cip, smac, cmac, tcp(sip, cip, dport, sport_c, sseq + 1, seq, 0x10)))
    return t + rtt * (3 + n_data * 2)


def lookup(c, t, client, cm, server, sm, name, answers, tid, rcode=0, delay=0.03, respond=True):
    sp = random.randint(20000, 60000)
    c.add(t, eth(sm, cm, 0x0800, ipv4(client, server, 17, udp(client, server, sp, 53, dns_q(tid, name)))))
    if respond:
        c.add(t + delay, eth(cm, sm, 0x0800, ipv4(server, client, 17, udp(server, client, 53, sp, dns_r(tid, name, answers, rcode)))))
    return sp


def arp_resolve(c, t, who, whom):
    c.add(t, eth("ff:ff:ff:ff:ff:ff", who[1], 0x0806, arp(1, who[1], who[0], "00:00:00:00:00:00", whom[0])))
    c.add(t + 0.001, eth(who[1], whom[1], 0x0806, arp(2, whom[1], whom[0], who[1], who[0])))


def dhcp_exchange(c, t, client_mac, server, smac, yi, router, dns, xid):
    c.add(t, eth("ff:ff:ff:ff:ff:ff", client_mac, 0x0800, ipv4("0.0.0.0", "255.255.255.255", 17, udp("0.0.0.0", "255.255.255.255", 68, 67, dhcp(1, xid, client_mac, "0.0.0.0", 1)))))
    c.add(t + 0.02, eth(client_mac, smac, 0x0800, ipv4(server, yi, 17, udp(server, yi, 67, 68, dhcp(2, xid, client_mac, yi, 2, server, router, dns)))))
    c.add(t + 0.05, eth(smac, client_mac, 0x0800, ipv4("0.0.0.0", "255.255.255.255", 17, udp("0.0.0.0", "255.255.255.255", 68, 67, dhcp(1, xid, client_mac, "0.0.0.0", 3, server)))))
    c.add(t + 0.07, eth(client_mac, smac, 0x0800, ipv4(server, yi, 17, udp(server, yi, 67, 68, dhcp(2, xid, client_mac, yi, 5, server, router, dns)))))


def normal(c, t=T):
    dhcp_exchange(c, t, H["pc1"][1], GW, GWM, H["pc1"][0], GW, GW, 0x1111)
    arp_resolve(c, t + 1, H["pc1"], (GW, GWM))
    for i, name in enumerate(["example.com", "docs.example.org", "mail.example.net"]):
        lookup(c, t + 2 + i, H["pc1"][0], H["pc1"][1], GW, GWM, name, [WEB], 100 + i)
        conn(c, t + 2.1 + i, H["pc1"][0], H["pc1"][1], WEB, GWM, 40000 + i, 443)
    for i in range(6):   # a busy browser: many connections, same port, all completed (must NOT look like a scan)
        conn(c, t + 6 + i * 0.1, H["pc2"][0], H["pc2"][1], WEB, GWM, 41000 + i, 443, n_data=2)
    return c


def flaky(c, t=T):
    """Outage-style faults only: loss, resets, DNS trouble, slow handshakes, MTU."""
    pc, srv = H["pc2"], H["srv"]
    # retransmissions on a lossy link (same seq re-sent) incl. big segments
    f = lambda s, d, sm, dm, seg: eth(dm, sm, 0x0800, ipv4(s, d, 6, seg))
    c.add(t, f(pc[0], srv[0], pc[1], srv[1], tcp(pc[0], srv[0], 42000, 8080, 1000, 0, 0x02, mss=1460)))
    c.add(t + 0.05, f(srv[0], pc[0], srv[1], pc[1], tcp(srv[0], pc[0], 8080, 42000, 7000, 1001, 0x12, mss=1460)))
    c.add(t + 0.1, f(pc[0], srv[0], pc[1], srv[1], tcp(pc[0], srv[0], 42000, 8080, 1001, 7001, 0x10)))
    for k, dt in enumerate([0.2, 0.7, 1.7, 3.7, 7.7, 15.7]):    # exponential backoff
        c.add(t + dt, f(pc[0], srv[0], pc[1], srv[1], tcp(pc[0], srv[0], 42000, 8080, 1001, 7001, 0x18, b"y" * 1400)))
    # server that never answers (SYN retransmits)
    for dt in (0, 1, 3, 7):
        c.add(t + 1 + dt, f(pc[0], "192.168.1.99", pc[1], "02:00:00:00:00:99", tcp(pc[0], "192.168.1.99", 43000, 22, 5000, 0, 0x02)))
    # service refused (RST) three times
    for i in range(4):
        c.add(t + 2 + i, f(pc[0], srv[0], pc[1], srv[1], tcp(pc[0], srv[0], 44000 + i, 3306, 10, 0, 0x02)))
        c.add(t + 2.001 + i, f(srv[0], pc[0], srv[1], pc[1], tcp(srv[0], pc[0], 3306, 44000 + i, 0, 11, 0x14)))
    # DNS: timeouts + NXDOMAIN
    for i in range(4):
        lookup(c, t + 3 + i, pc[0], pc[1], "192.168.1.2", "02:00:00:00:00:02", f"intranet{i}.corp.local", [], 200 + i, respond=False)
    for i in range(4):
        lookup(c, t + 8 + i, pc[0], pc[1], GW, GWM, f"typo{i}.example.com", [], 300 + i, rcode=3)
    for i in range(3):
        lookup(c, t + 13 + i, pc[0], pc[1], GW, GWM, f"slow{i}.example.com", [WEB], 400 + i, delay=2.4)
    # slow handshakes to an overseas server
    for i in range(3):
        conn(c, t + 17 + i * 4, pc[0], pc[1], "203.0.113.9", GWM, 45000 + i, 443, rtt=1.6, n_data=1)
    # MTU: router says "too big"
    inner = ipv4(pc[0], "203.0.113.9", 6, tcp(pc[0], "203.0.113.9", 45000, 443, 1, 1, 0x18, b"z" * 8))[:28]
    for i in range(2):
        icmp = struct.pack(">BBHHH", 3, 4, 0, 0, 1400) + inner
        icmp = icmp[:2] + struct.pack(">H", csum(icmp)) + icmp[4:]
        c.add(t + 30 + i, eth(pc[1], GWM, 0x0800, ipv4(GW, pc[0], 1, icmp)))
    return c


def arp_spoof(c, t=T):
    atk = ("192.168.1.66", "de:ad:be:ef:00:66")
    victim = H["pc1"]
    arp_resolve(c, t, victim, (GW, GWM))
    arp_resolve(c, t + 0.1, H["pc2"], (GW, GWM))
    for i in range(14):   # poison victim (claims to be gateway) and gateway (claims to be victim)
        c.add(t + 2 + i * 2, eth(victim[1], atk[1], 0x0806, arp(2, atk[1], GW, victim[1], victim[0])))
        c.add(t + 2.5 + i * 2, eth(GWM, atk[1], 0x0806, arp(2, atk[1], victim[0], GWM, GW)))
    # side effect: victim's traffic to the Internet now stalls
    f = lambda s, d, sm, dm, seg: eth(dm, sm, 0x0800, ipv4(s, d, 6, seg))
    c.add(t + 3, f(victim[0], WEB, victim[1], atk[1], tcp(victim[0], WEB, 46000, 443, 1000, 0, 0x02, mss=1460)))
    c.add(t + 3.05, f(WEB, victim[0], GWM, victim[1], tcp(WEB, victim[0], 443, 46000, 9000, 1001, 0x12)))
    c.add(t + 3.1, f(victim[0], WEB, victim[1], atk[1], tcp(victim[0], WEB, 46000, 443, 1001, 9001, 0x10)))
    for dt in (0.3, 0.9, 2, 4, 8):
        c.add(t + 3.1 + dt, f(victim[0], WEB, victim[1], atk[1], tcp(victim[0], WEB, 46000, 443, 1001, 9001, 0x18, b"q" * 600)))
    return c


def port_scan(c, t=T):
    atk, tgt = ("10.0.0.99", "de:ad:be:ef:00:99"), H["srv"]
    open_ports = {22, 80, 443}
    for i, port in enumerate(range(1, 81)):
        tt = t + i * 0.05
        sp = 50000
        c.add(tt, eth(tgt[1], atk[1], 0x0800, ipv4(atk[0], tgt[0], 6, tcp(atk[0], tgt[0], sp + i, port, 777, 0, 0x02))))
        if port in open_ports:
            c.add(tt + 0.001, eth(atk[1], tgt[1], 0x0800, ipv4(tgt[0], atk[0], 6, tcp(tgt[0], atk[0], port, sp + i, 99, 778, 0x12))))
            c.add(tt + 0.002, eth(tgt[1], atk[1], 0x0800, ipv4(atk[0], tgt[0], 6, tcp(atk[0], tgt[0], sp + i, port, 778, 100, 0x04))))
        else:
            c.add(tt + 0.001, eth(atk[1], tgt[1], 0x0800, ipv4(tgt[0], atk[0], 6, tcp(tgt[0], atk[0], port, sp + i, 0, 778, 0x14))))
    return c


def dns_hijack(c, t=T):
    pc = H["pc3"]
    evil, real = "6.6.6.6", WEB
    for i, name in enumerate(["bank.example.com", "login.example.com", "mail.example.com"]):
        sp = lookup(c, t + i * 3, pc[0], pc[1], GW, GWM, name, [real], 500 + i, delay=0.060)   # real answer, slower
        # forged answer is faster and comes from a device the client never asked
        c.add(t + i * 3 + 0.012, eth(pc[1], "de:ad:be:ef:00:77", 0x0800, ipv4(GW, pc[0], 17, udp(GW, pc[0], 53, sp, dns_r(500 + i, name, [evil])))))
    return c


def rogue_dhcp(c, t=T):
    dhcp_exchange(c, t, H["pc1"][1], GW, GWM, H["pc1"][0], GW, GW, 0x2001)
    dhcp_exchange(c, t + 20, H["pc2"][1], GW, GWM, H["pc2"][0], GW, GW, 0x2002)
    # the rogue answers a client, handing out itself as gateway and DNS
    rg = ("192.168.1.200", "de:ad:be:ef:00:c8")
    for k, (pc, off) in enumerate([(H["pc3"], 40), (H["pc1"], 60)]):
        dhcp_exchange(c, t + off, pc[1], rg[0], rg[1], pc[0], rg[0], rg[0], 0x2100 + k)
    return c


def dup_ip(c, t=T):
    a, b = ("192.168.1.30", "02:00:00:00:00:30"), ("192.168.1.30", "02:00:00:00:00:31")
    asker = H["pc1"]
    for i in range(4):   # both answer only when asked
        arp_resolve(c, t + i * 5, asker, a)
        c.add(t + i * 5 + 0.002, eth(asker[1], b[1], 0x0806, arp(2, b[1], b[0], asker[1], asker[0])))
    return c


def merged(*fns):
    c = Cap()
    for i, fn in enumerate(fns):
        fn(c, T + i * 0.0)
    return c


def malformed():
    """Robustness demo: valid header, one good packet, then garbage record lengths."""
    c = normal(Cap())
    c.pk = c.pk[:5]
    c.save("malformed_tmp.pcap")
    raw = open(os.path.join(OUT, "malformed_tmp.pcap"), "rb").read()
    os.remove(os.path.join(OUT, "malformed_tmp.pcap"))
    raw += struct.pack("<IIII", 1, 1, 0x7FFFFFF0, 0x7FFFFFF0) + b"\xff" * 20
    open(os.path.join(OUT, "malformed.pcap"), "wb").write(raw)
    print("wrote malformed.pcap (deliberately corrupt)")


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    normal(Cap()).save("01_normal.pcap")
    flaky(Cap()).save("02_outage_faults.pcap")
    arp_spoof(Cap()).save("03_arp_spoofing.pcap")
    port_scan(Cap()).save("04_port_scan.pcap")
    dns_hijack(Cap()).save("05_dns_hijack.pcap")
    rogue_dhcp(Cap()).save("06_rogue_dhcp.pcap")
    dup_ip(Cap()).save("07_duplicate_ip.pcap")
    m = Cap()
    flaky(m, T); port_scan(m, T + 40); arp_spoof(m, T + 60)
    m.save("08_mixed_incident.pcap")
    malformed()
