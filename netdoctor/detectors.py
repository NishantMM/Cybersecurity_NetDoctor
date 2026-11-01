"""Detection logic (all original). Each detector takes the list of dissected
packets plus a shared Context and returns a list of Finding objects.

False-alarm control: every rule has a minimum evidence count, scan sources are
excluded from fault rules, and attack rules need behaviour a plain outage does
not produce (unsolicited ARP replies, port fan-out, conflicting DNS answers...).
"""
from __future__ import annotations
import ipaddress
import statistics
from collections import Counter, defaultdict

from .dissect import SYN, ACK, RST, FIN
from .model import Finding

# ---- tunables (documented in README) ------------------------------------
SCAN_MIN_PORTS = 15        # distinct ports/hosts probed ...
SCAN_WINDOW = 10.0         # ... within this many seconds
SCAN_MIN_INCOMPLETE = 0.7  # share of probes that never completed a handshake
RETRANS_MIN = 3
RST_MIN = 3
DNS_FAIL_MIN = 3
SLOW_SECONDS = 1.0
ARP_SPOOF_MIN_UNSOLICITED = 3


class Context:
    def __init__(self, pkts):
        self.pkts = pkts
        self.t0 = pkts[0].ts if pkts else 0.0
        self.t1 = pkts[-1].ts if pkts else 0.0
        self.scanners = set()


def _make(code, kind, title, sev, conf, summary, cause, fix, pk, hosts, **details):
    pk = list(pk)
    return Finding(code, kind, title, sev, conf, summary, cause, fix,
                   [p.no for p in pk], set(h for h in hosts if h),
                   min(p.ts for p in pk), max(p.ts for p in pk), details).finalize()


def _fmt_list(items, n=5):
    items = list(items)
    s = ", ".join(str(i) for i in items[:n])
    return s + (f" and {len(items) - n} more" if len(items) > n else "")


# =========================================================== ATTACKS =====
def detect_port_scan(pk, ctx):
    syns = [p for p in pk if p.is_tcp and p.flags & SYN and not p.flags & ACK]
    synack, completed = set(), set()
    rst_to = defaultdict(int)
    for p in pk:
        if not p.is_tcp:
            continue
        if p.flags & SYN and p.flags & ACK:
            synack.add((p.dst, p.dport, p.src, p.sport))
        elif p.flags & RST:
            rst_to[(p.dst, p.dport, p.src, p.sport)] += 1
    for p in pk:
        if p.is_tcp and p.flags & ACK and not p.flags & (SYN | RST) and \
                (p.src, p.sport, p.dst, p.dport) in synack:
            completed.add((p.src, p.sport, p.dst, p.dport))
    by_src = defaultdict(list)
    for p in syns:
        by_src[p.src].append(p)
    out = []
    for src, probes in by_src.items():
        best = None
        for mode, keyf, targetf in (("port scan", lambda p: p.dst, lambda p: p.dport),
                                    ("host sweep", lambda p: p.dport, lambda p: p.dst)):
            groups = defaultdict(dict)
            for p in probes:
                groups[keyf(p)].setdefault(targetf(p), p)  # first probe per target
            for gk, first in groups.items():
                lst = sorted(first.values(), key=lambda p: p.ts)
                j = 0
                for i in range(len(lst)):
                    while lst[i].ts - lst[j].ts > SCAN_WINDOW:
                        j += 1
                    if i - j + 1 >= SCAN_MIN_PORTS:
                        window = lst[j:i + 1]
                        if best is None or len(window) > len(best[2]):
                            best = (mode, gk, window)
        if not best:
            continue
        mode, gk, window = best
        done = sum(1 for p in window if (p.src, p.sport, p.dst, p.dport) in completed)
        if 1 - done / len(window) < SCAN_MIN_INCOMPLETE:
            continue                      # many real connections: not a scan
        opened = sorted({p.dport for p in window if (p.src, p.sport, p.dst, p.dport) in synack})
        closed = sum(1 for p in window if rst_to.get((p.src, p.sport, p.dst, p.dport)))
        ctx.scanners.add(src)
        dur = window[-1].ts - window[0].ts
        what = (f"{len(window)} different TCP ports on {gk}" if mode == "port scan"
                else f"port {gk} on {len(window)} different hosts")
        out.append(_make(
            "port_scan", "attack", f"Port scan from {src}", "high",
            min(0.99, 0.75 + len(window) / 200),
            f"{src} knocked on {what} within {dur:.1f} seconds, and almost none of the "
            f"connections were completed. {closed} probes were refused, and open ports found: "
            f"{_fmt_list(opened) or 'none'}. Real programs do not behave this way; this is "
            f"someone mapping what is reachable.",
            "A scanning tool (nmap-style) run by an attacker, a compromised machine, or an "
            "unauthorised/forgotten security scan.",
            f"Find out who owns {src}. If it is not an approved scan, block it at the firewall "
            f"and check that machine for malware. Close or firewall every port you do not need.",
            window, {src, gk if mode == "port scan" else ""}, mode=mode, open_ports=opened,
            probes=len(window), seconds=round(dur, 2)))
    return out


def detect_arp(pk, ctx):
    pending, asked = {}, Counter()     # (asker mac, asked ip) -> time of the open request
    claims = defaultdict(lambda: defaultdict(list))   # ip -> mac -> [(pkt, solicited)]
    for p in pk:
        if p.arp_op == 1:
            pending[(p.arp_sha, p.arp_tpa)] = [p.ts, 0]
            asked[p.arp_tpa] += 1
            if p.arp_spa not in ("0.0.0.0", ""):
                claims[p.arp_spa][p.arp_sha].append((p, True))
        elif p.arp_op == 2 and p.arp_spa not in ("0.0.0.0", ""):
            req = pending.get((p.arp_tha, p.arp_spa))
            # an honest reply comes right after the request; two devices answering the
            # same request (duplicate IP) is still "asked for", a later flood is not
            solicited = req is not None and p.ts - req[0] <= 1.0 and req[1] < 2
            if req is not None:
                req[1] += 1
            claims[p.arp_spa][p.arp_sha].append((p, solicited))
    gateway = asked.most_common(1)[0][0] if asked else None
    out, spoofs = [], defaultdict(list)
    for ip, macs in claims.items():
        if len(macs) < 2:
            continue
        unsol = {m: [p for p, s in lst if not s] for m, lst in macs.items()}
        attacker = max(unsol, key=lambda m: len(unsol[m]))
        legit = [m for m in macs if m != attacker]
        if len(unsol[attacker]) >= ARP_SPOOF_MIN_UNSOLICITED:
            spoofs[attacker].append((ip, legit[0], unsol[attacker], macs))
        else:
            ev = [p for m in macs for p, _ in macs[m]]
            out.append(_make(
                "duplicate_ip", "fault", f"Duplicate IP address {ip}", "medium", 0.8,
                f"Two devices ({_fmt_list(macs)}) both answer to {ip}. Each is replying "
                f"only when asked, with no flood of unrequested replies, which looks like a "
                f"configuration mistake and not an attack. Connections to {ip} will randomly "
                f"hit the wrong device, causing drops and slowness.",
                "A static IP set on a device inside the DHCP range, or two devices given the "
                "same static address.",
                f"Find both devices by MAC, give one of them a different address or a DHCP "
                f"reservation, and exclude static addresses from the DHCP pool.",
                ev, {ip}, macs=list(macs)))
    for attacker, items in spoofs.items():
        ips = [ip for ip, *_ in items]
        n_unsol = sum(len(u) for _, _, u, _ in items)
        victims = {p.arp_tpa for _, _, u, _ in items for p in u}
        ev = [p for _, _, _, macs in items for p, _ in macs[attacker]]
        ev += [macs[legit][0][0] for _, legit, _, macs in items]
        two_way = len(ips) >= 2
        conf = 0.7 + (0.1 if n_unsol >= 10 else 0) + (0.15 if two_way else 0)
        names = ", ".join(f"{ip} (the gateway)" if ip == gateway else ip for ip in ips[:4])
        out.append(_make(
            "arp_spoofing", "attack", f"ARP spoofing by {attacker}", "high", min(conf, 0.98),
            f"Device {attacker} keeps announcing that it owns {names}, addresses that belong to other "
            f"devices. It sent {n_unsol} ARP replies nobody asked for. Computers that believe it send "
            f"their traffic to the impostor instead of the real device, so it can read or alter that "
            f"traffic (man-in-the-middle)." +
            (" It poisons both sides of a conversation at once, the typical man-in-the-middle setup." if two_way else ""),
            "An attacker on the local network running an ARP-poisoning tool.",
            f"Locate the device with MAC {attacker} (switch port table) and disconnect it. Enable Dynamic ARP "
            f"Inspection / port security if your switch supports it, and use static ARP entries for the gateway "
            f"on critical machines.",
            ev, {*ips, *victims}, attacker_mac=attacker, impersonated=ips, unsolicited=n_unsol))
    return out


def detect_dns_hijack(pk, ctx):
    queries, responses = {}, defaultdict(list)
    for p in pk:
        if not p.dns:
            continue
        d = p.dns
        if not d["qr"]:
            queries.setdefault((p.src, d["id"], d["qname"]), p)
        else:
            responses[(p.dst, d["id"], d["qname"])].append(p)
    hits, domains, forged_ips, ev, hosts = [], set(), set(), [], set()
    for key, resps in responses.items():
        q = queries.get(key)
        answer_sets = {(r.src, r.dns["answers"]) for r in resps if r.dns["rcode"] == 0 and r.dns["answers"]}
        conflicting = len({a for _, a in answer_sets}) >= 2
        wrong_server = q is not None and any(r.src != q.dst and r.dns["answers"] for r in resps)
        if conflicting or wrong_server:
            domains.add(key[2])
            hosts |= {key[0], *(r.src for r in resps)}
            ev += resps + ([q] if q else [])
            if conflicting:       # the forged reply usually wins the race, so it is the first to arrive
                forged_ips |= set(min(resps, key=lambda r: r.ts).dns["answers"])
            else:
                for r in resps:
                    if r.src != q.dst:
                        forged_ips |= set(r.dns["answers"])
            hits.append(key)
    if not hits:
        return []
    return [_make(
        "dns_hijack", "attack", "DNS hijacking: forged answers detected", "high", 0.85,
        f"For {len(domains)} lookup(s) ({_fmt_list(sorted(domains), 3)}) the computer received "
        f"conflicting answers, or an answer from a server it never asked. A forged reply "
        f"arrives first and sends the user to {_fmt_list(sorted(forged_ips))} (suspect address) instead of the real site. "
        f"That is how phishing redirects and traffic interception are done.",
        "A DNS spoofing tool on the network, a compromised router/resolver, or a malicious "
        "rogue DHCP server pointing clients to a hostile DNS.",
        "Do not trust those sites until fixed. Check the router's DNS settings, look for a "
        "rogue DHCP server, switch to DNS-over-HTTPS/TLS or DNSSEC-validating resolvers, and "
        "investigate " + _fmt_list(sorted(hosts - {h[0] for h in hits}), 3) + ".",
        ev, hosts, domains=sorted(domains), suspicious_answers=sorted(forged_ips))]


def detect_rogue_dhcp(pk, ctx):
    servers = defaultdict(list)
    for p in pk:
        if p.dhcp and p.dhcp["type"] in (2, 5):
            servers[p.dhcp["server_id"] or p.src].append(p)
    if len(servers) < 2:
        return []
    ranked = sorted(servers, key=lambda s: (-len(servers[s]), servers[s][0].ts))
    legit, others = ranked[0], ranked[1:]
    L = servers[legit][0].dhcp
    out = []
    for s in others:
        S = servers[s][0].dhcp
        differs = (S["router"] != L["router"]) or (S["dns"] != L["dns"])
        ev = servers[s] + servers[legit][:2]
        if differs:
            out.append(_make(
                "rogue_dhcp", "attack", f"Rogue DHCP server at {s}", "high", 0.85,
                f"Besides the normal DHCP server {legit}, a second device {s} is handing out "
                f"network settings, and its settings differ (gateway {S['router'] or '-'}, DNS "
                f"{S['dns'] or '-'} instead of {L['router'] or '-'} / {L['dns'] or '-'}). A client "
                f"that accepts them sends all its traffic through, or asks its DNS questions to, "
                f"the impostor.",
                "An attacker (or a personal router plugged in by mistake) offering leases to "
                "redirect or spy on traffic.",
                f"Unplug/locate {s} (use the switch MAC table), enable DHCP snooping so only the "
                f"trusted port can answer, and renew leases on affected clients.",
                ev, {s, legit}, rogue=s, trusted=legit))
        else:
            out.append(_make(
                "second_dhcp", "fault", f"Second DHCP server at {s}", "medium", 0.7,
                f"Two DHCP servers ({legit} and {s}) answer clients. Their settings match, so this "
                f"looks like a misconfiguration, but overlapping pools cause duplicate addresses "
                f"and random connection problems.",
                "A router/access point with DHCP left switched on.",
                f"Disable DHCP on {s} (or on {legit}) so only one server remains.",
                ev, {s, legit}, second=s, primary=legit))
    return out


# ============================================================ FAULTS =====
def detect_tcp_faults(pk, ctx):
    out = []
    first_seen, retrans, data_segs = {}, defaultdict(list), Counter()
    syn_retrans, synack_from = defaultdict(list), set()
    rsts = defaultdict(list)
    for p in pk:
        if not p.is_tcp:
            continue
        if p.flags & SYN and p.flags & ACK:
            synack_from.add((p.src, p.sport, p.dst))
        if p.flags & RST:
            if p.dst not in ctx.scanners:
                rsts[(p.src, p.sport)].append(p)
            continue
        if p.payload > 0 or p.flags & SYN:
            k = (p.src, p.sport, p.dst, p.dport, p.seq, p.flags & SYN, p.payload)
            if k in first_seen and p.ts > first_seen[k]:
                (syn_retrans if p.flags & SYN else retrans)[
                    (p.src, p.dst) if not p.flags & SYN else (p.src, p.dst, p.dport)].append(p)
            else:
                first_seen[k] = p.ts
                if p.payload > 0:
                    data_segs[(p.src, p.dst)] += 1
    for (src, dst), lst in retrans.items():
        if len(lst) < RETRANS_MIN:
            continue
        ratio = len(lst) / max(1, data_segs[(src, dst)] + len(lst))
        big = sum(1 for p in lst if p.payload >= 1300) / len(lst)
        sev = "high" if ratio >= 0.1 or len(lst) >= 10 else "medium"
        out.append(_make(
            "tcp_retransmissions", "fault", f"TCP retransmissions {src} → {dst}", sev, 0.9,
            f"{src} had to resend data to {dst} {len(lst)} times ({ratio:.0%} of its segments) "
            f"because the other side never confirmed receiving it. The traffic is not diverse "
            f"(no port fan-out, no spoofing), which points to packet loss on the path and not to an attack.",
            "Packet loss: congested or failing link, bad cable/Wi-Fi signal, overloaded device, "
            "or a firewall dropping packets.",
            "Ping/traceroute to the destination to find where loss begins, check cables and Wi-Fi "
            "signal, look at interface error counters, and check for a saturated link.",
            lst, {src, dst}, retransmissions=len(lst), ratio=round(ratio, 3)))
        if big >= 0.8 and len(lst) >= RETRANS_MIN:
            out.append(_make(
                "mtu_blackhole", "fault", f"Possible MTU mismatch {src} → {dst}", "medium", 0.5,
                f"{big:.0%} of the resent segments are large (1300+ bytes). Small packets work but "
                f"big ones vanish, the classic sign of a path whose MTU is smaller than expected.",
                "A tunnel/VPN/PPPoE link with a smaller MTU where ICMP 'fragmentation needed' "
                "messages are blocked.",
                "Lower the MTU/MSS (for example MSS clamping to 1360-1452) on the router or tunnel and allow "
                "ICMP type 3 code 4 through firewalls.", lst, {src, dst}))
    for (src, dst, port), lst in syn_retrans.items():
        if len(lst) >= 2 and (dst, port, src) not in synack_from:
            out.append(_make(
                "unreachable_server", "fault", f"{dst}:{port} does not answer {src}", "high", 0.9,
                f"{src} tried to open a connection to {dst} port {port} and re-sent its request "
                f"{len(lst)} times with no reply at all. The service is unreachable.",
                "The server is down, a firewall is silently dropping the traffic, or routing is broken.",
                f"Check that {dst} is powered on and that port {port} is listening, then test the "
                f"route and any firewall rules between the two.", lst, {src, dst}, port=port))
    for (src, sport), lst in rsts.items():
        if len(lst) < RST_MIN:
            continue
        refused = [p for p in lst if (src, sport, p.dst) not in synack_from]
        mode = "refused" if len(refused) > len(lst) / 2 else "aborted"
        out.append(_make(
            "tcp_resets", "fault", f"Connections to {src}:{sport} are being reset", "medium", 0.8,
            (f"{src} port {sport} rejected {len(lst)} connection attempts straight away (RST): "
             f"nothing is listening there or a firewall is rejecting it."
             if mode == "refused" else
             f"{len(lst)} established connections with {src}:{sport} were cut off abruptly "
             f"with a reset instead of a normal close."),
            ("The service is stopped, on a different port, or a firewall rejects the traffic."
             if mode == "refused" else
             "An application crash, a load-balancer/firewall idle timeout, or an overloaded server. "
             "(Occasionally also forged resets: check no other finding names these hosts.)"),
            ("Start the service or correct the port/firewall rule."
             if mode == "refused" else
             "Check the server's logs around those times and any idle-timeout settings on middleboxes."),
            lst, {src, *(p.dst for p in lst)}, mode=mode, count=len(lst)))
    return out


def detect_dns_faults(pk, ctx):
    out = []
    queries, responses = {}, defaultdict(list)
    for p in pk:
        if p.dns:
            k = (p.src, p.dns["id"], p.dns["qname"]) if not p.dns["qr"] else (p.dst, p.dns["id"], p.dns["qname"])
            if p.dns["qr"]:
                responses[k].append(p)
            else:
                queries.setdefault(k, p)
    names = {2: "SERVFAIL (server could not answer)", 3: "NXDOMAIN (name does not exist)", 5: "REFUSED"}
    fails = defaultdict(list)
    for lst in responses.values():
        for r in lst:
            if r.dns["rcode"] in names:
                fails[r.dns["rcode"]].append(r)
    for rc, lst in fails.items():
        if len(lst) >= DNS_FAIL_MIN:
            top = Counter(r.dns["qname"] for r in lst).most_common(3)
            out.append(_make(
                "dns_failures", "fault", f"DNS lookups failing: {names[rc]}", "medium", 0.8,
                f"{len(lst)} DNS lookups returned {names[rc]}; most affected names: "
                f"{_fmt_list([n for n, _ in top])}. Programs asking for these names cannot connect.",
                "A mistyped or expired domain, a broken DNS server/forwarder, or a misconfigured search domain."
                if rc == 3 else "The DNS server is overloaded, misconfigured or refusing this client.",
                "Test with `nslookup <name> <server>`, try a different resolver, and check the DNS server logs/settings.",
                lst, {r.src for r in lst} | {r.dst for r in lst}, rcode=rc))
    end = ctx.t1 - 2.0
    unanswered = defaultdict(list)
    for k, q in queries.items():
        if k not in responses and q.ts < end:
            unanswered[q.dst].append(q)
    for server, lst in unanswered.items():
        if len(lst) >= DNS_FAIL_MIN:
            out.append(_make(
                "dns_timeouts", "fault", f"DNS server {server} is not answering", "high", 0.85,
                f"{len(lst)} DNS questions sent to {server} never got a reply. Without DNS most "
                f"websites and services appear 'down' even though the link itself works.",
                "DNS server down or unreachable, traffic to port 53 blocked, or the server is overloaded.",
                f"Check that {server} is up and reachable, try another resolver (e.g. the router or 1.1.1.1) "
                f"and review firewall rules for UDP/TCP port 53.",
                lst, {server, *(q.src for q in lst)}, unanswered=len(lst)))
    slow = []
    for k, q in queries.items():
        r = responses.get(k)
        if r and r[0].ts - q.ts > SLOW_SECONDS:
            slow.append((r[0].ts - q.ts, q, r[0]))
    if len(slow) >= 2:
        med = statistics.median(d for d, _, _ in slow)
        out.append(_make(
            "slow_dns", "fault", "Unusually slow DNS answers", "low", 0.7,
            f"{len(slow)} DNS lookups took over {SLOW_SECONDS:.0f} s to answer (median {med:.1f} s). "
            f"Every web page or app start has to wait for this, so the network feels slow.",
            "An overloaded or distant DNS server, or a lossy path to it.",
            "Use a closer/faster resolver, check packet loss towards the DNS server.",
            [x for _, q, r in slow for x in (q, r)], {q.dst for _, q, _ in slow}, median_seconds=round(med, 2)))
    return out


def detect_latency(pk, ctx):
    syn_ts, rtts = {}, defaultdict(list)
    for p in pk:
        if not p.is_tcp:
            continue
        if p.flags & SYN and not p.flags & ACK:
            syn_ts.setdefault((p.src, p.sport, p.dst, p.dport), p)
        elif p.flags & SYN and p.flags & ACK:
            s = syn_ts.get((p.dst, p.dport, p.src, p.sport))
            if s:
                rtts[(p.src, p.sport)].append((p.ts - s.ts, s, p))
    out = []
    for (srv, port), lst in rtts.items():
        slow = [x for x in lst if x[0] > SLOW_SECONDS]
        if len(slow) >= 2:
            med = statistics.median(d for d, _, _ in slow)
            out.append(_make(
                "slow_handshake", "fault", f"Very slow connection setup to {srv}:{port}", "medium", 0.75,
                f"{len(slow)} connections to {srv}:{port} needed over {SLOW_SECONDS:.0f} s just to "
                f"get the first reply (median {med:.1f} s). Users see this as 'the site hangs before loading'.",
                "A congested or distant link, an overloaded server, or lost SYN packets that had to be re-sent.",
                "Test round-trip time with ping/mtr to the server, check server load and link utilisation.",
                [x for _, s, a in slow for x in (s, a)], {srv, *(s.src for _, s, _ in slow)},
                median_seconds=round(med, 2)))
    return out


def detect_icmp_mtu(pk, ctx):
    by_router = defaultdict(list)
    for p in pk:
        if p.proto == 1 and p.icmp_type == 3 and p.icmp_code == 4:
            by_router[p.src].append(p)
    out = []
    for router, lst in by_router.items():
        mtus = sorted({p.icmp_mtu for p in lst if p.icmp_mtu})
        out.append(_make(
            "mtu_mismatch", "fault", f"MTU mismatch reported by {router}", "medium", 0.9,
            f"{router} told senders {len(lst)} time(s) that their packets were too big to forward "
            f"(ICMP 'fragmentation needed'), advertising a maximum size of {_fmt_list(mtus) or 'unknown'} bytes. "
            f"Large transfers stall or are slow while small ones work.",
            "A link in the path (VPN/tunnel/PPPoE/jumbo-frame mismatch) has a smaller MTU than the endpoints assume.",
            f"Set the MTU on the endpoints (or clamp TCP MSS on the router) to at most {mtus[0] if mtus else 1400} bytes, "
            f"or fix the mismatched link.", lst, {router, *(p.dst for p in lst)}, mtus=mtus))
    return out


DETECTORS = [detect_port_scan, detect_arp, detect_dns_hijack, detect_rogue_dhcp,
             detect_tcp_faults, detect_dns_faults, detect_latency, detect_icmp_mtu]
