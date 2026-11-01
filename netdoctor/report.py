from __future__ import annotations
import html
import json

FLAGS = [(0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH")]


def describe(p, t0=0.0):
    """One-line packet summary used as evidence (time relative to capture start)."""
    t = f"#{p.no:<6} +{p.ts - t0:8.3f}s  "
    if p.arp_op:
        what = "who-has " + p.arp_tpa + " tell " + p.arp_spa if p.arp_op == 1 else f"{p.arp_spa} is-at {p.arp_sha}"
        return t + "ARP " + what
    if p.is_tcp:
        fl = ",".join(n for b, n in FLAGS if p.flags & b)
        return t + f"TCP {p.src}:{p.sport} -> {p.dst}:{p.dport} [{fl}] seq={p.seq} len={p.payload}"
    if p.dns:
        d = p.dns
        kind = f"response rcode={d['rcode']} {','.join(d['answers'])}" if d["qr"] else "query"
        return t + f"DNS {p.src} -> {p.dst} id={d['id']} {d['qname']} {kind}"
    if p.dhcp:
        return t + f"DHCP type={p.dhcp['type']} {p.src} -> {p.dst} server={p.dhcp['server_id']}"
    if p.proto == 1:
        return t + f"ICMP {p.src} -> {p.dst} type={p.icmp_type} code={p.icmp_code}"
    if p.is_udp:
        return t + f"UDP {p.src}:{p.sport} -> {p.dst}:{p.dport} len={p.payload}"
    return t + f"{p.src or p.eth_src} -> {p.dst or p.eth_dst} proto={p.proto}"


def to_text(res, filename=""):
    s = res["stats"]
    out = [f"NetDoctor report {('for ' + filename) if filename else ''}".strip(),
           f"{s['packets']} packets, {s['duration']} s, protocols: {s['protocols']}",
           f"VERDICT: {res['verdict']}", ""]
    for w in res["warnings"]:
        out.append(f"warning: {w}")
    by_no = {p.no: p for p in res["packets"]}
    t0 = res["packets"][0].ts if res["packets"] else 0.0
    for i, f in enumerate(res["findings"], 1):
        out += [f"[{i}] {f.kind.upper()} / {f.severity} / confidence {f.confidence:.0%}: {f.title}",
                f"    What happened : {f.summary}", f"    Likely cause  : {f.cause}",
                f"    Suggested fix : {f.fix}",
                f"    Evidence ({f.details['evidence_total']} packets, first {len(f.packets)} shown):"]
        out += ["      " + describe(by_no[n], t0) for n in f.packets[:8] if n in by_no]
        out.append("")
    return "\n".join(out)


def to_json(res):
    return json.dumps({"verdict": res["verdict"], "stats": res["stats"], "warnings": res["warnings"],
                       "findings": [f.to_dict() for f in res["findings"]]}, indent=2)


def to_html(res, filename=""):
    e = html.escape            # every capture-derived string is escaped: DNS names are attacker-controlled
    s, fl = res["stats"], res["findings"]
    by_no = {p.no: p for p in res["packets"]}
    pk = res["packets"]
    t0, t1 = (pk[0].ts, pk[-1].ts) if pk else (0, 1)
    span = max(t1 - t0, 1e-6)
    rows, cards = [], []
    for i, f in enumerate(fl, 1):
        left = 100 * (f.t_start - t0) / span
        width = max(1.0, 100 * (f.t_end - f.t_start) / span)
        rows.append(f'<div class="row"><a href="#f{i}" class="lbl">{i}. {e(f.title)}</a>'
                    f'<div class="track"><div class="bar {f.kind}" style="left:{left:.2f}%;width:{min(width, 100 - left):.2f}%"></div></div></div>')
        ev = "\n".join(e(describe(by_no[n], t0)) for n in f.packets if n in by_no)
        cards.append(f'''<section class="card {f.kind}" id="f{i}">
<h3><span class="tag {f.kind}">{e(f.kind.upper())}</span> {e(f.title)}
<small>{e(f.severity)} severity · {f.confidence:.0%} confidence</small></h3>
<p><b>What happened:</b> {e(f.summary)}</p><p><b>Likely cause:</b> {e(f.cause)}</p>
<p><b>Suggested fix:</b> {e(f.fix)}</p>
<details><summary>Evidence: {f.details["evidence_total"]} packets (showing {len(f.packets)})</summary><pre>{ev}</pre></details></section>''')
    warn = "".join(f"<p class='warn'>⚠ {e(w)}</p>" for w in res["warnings"])
    cls = "bad" if s["attacks"] else "mid" if s["faults"] else "ok"
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>NetDoctor report</title><style>
body{{font:15px/1.5 system-ui,sans-serif;max-width:980px;margin:2rem auto;padding:0 1rem;color:#1a2330}}
.verdict{{padding:1rem 1.2rem;border-radius:8px;font-weight:600;font-size:1.1rem}}
.verdict.bad{{background:#fde8e8;border-left:6px solid #c62828}}.verdict.mid{{background:#fff4e0;border-left:6px solid #ef8f00}}.verdict.ok{{background:#e6f5ea;border-left:6px solid #2e7d32}}
.card{{border:1px solid #d5dbe3;border-left-width:6px;border-radius:8px;padding:.2rem 1rem 1rem;margin:1rem 0}}
.card.attack{{border-left-color:#c62828}}.card.fault{{border-left-color:#ef8f00}}
.tag{{font-size:.7rem;padding:.15rem .45rem;border-radius:4px;color:#fff}}.tag.attack{{background:#c62828}}.tag.fault{{background:#ef8f00}}
small{{color:#667;font-weight:400;margin-left:.5rem}}pre{{background:#0f1720;color:#d6e2f0;padding:.8rem;overflow:auto;border-radius:6px;font-size:12px}}
.row{{display:flex;align-items:center;margin:3px 0}}.lbl{{width:42%;font-size:13px;color:#1a2330;text-decoration:none;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.track{{position:relative;flex:1;height:14px;background:#eef1f5;border-radius:7px}}.bar{{position:absolute;top:0;height:14px;border-radius:7px;min-width:6px}}
.bar.attack{{background:#c62828}}.bar.fault{{background:#ef8f00}}.warn{{color:#8a5a00}}</style></head><body>
<h1>NetDoctor report</h1><p>{e(filename)} · {s["packets"]} packets · {s["duration"]} s · {e(json.dumps(s["protocols"]))}</p>
<div class="verdict {cls}">{e(res["verdict"])}</div>{warn}
<h2>Timeline</h2>{"".join(rows) or "<p>No findings.</p>"}
<h2>Findings</h2>{"".join(cards)}</body></html>'''
