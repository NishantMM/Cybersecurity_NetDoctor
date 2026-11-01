"""Own capture-file reader (classic pcap + pcapng). Pure stdlib, defensive.

Safety: size cap, packet cap, per-record length cap, every read is
bounds-checked, corrupt tails are reported as warnings instead of crashing.
"""
from __future__ import annotations
import os
import struct
from dataclasses import dataclass

MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_PACKETS = 500_000
MAX_RECORD = 262_144
LINK_ETHERNET, LINK_SLL = 1, 113


class CaptureError(Exception):
    """The file is not a usable capture."""


@dataclass
class RawPacket:
    no: int
    ts: float
    data: bytes
    linktype: int
    orig_len: int


_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}


def read_capture(path, max_packets=MAX_PACKETS, max_bytes=MAX_FILE_BYTES):
    """Return (packets, warnings). Raises CaptureError for unusable input."""
    try:
        size = os.path.getsize(path)
    except OSError as e:
        raise CaptureError(f"cannot open file: {e.strerror}") from None
    if size == 0:
        raise CaptureError("file is empty")
    if size > max_bytes:
        raise CaptureError(f"file too large ({size} bytes, limit {max_bytes})")
    with open(path, "rb") as f:
        data = f.read()
    magic = data[:4]
    warnings = []
    if magic in _PCAP_MAGICS:
        pkts = _read_pcap(data, *_PCAP_MAGICS[magic], max_packets, warnings)
    elif magic == b"\x0a\x0d\x0d\x0a":
        pkts = _read_pcapng(data, max_packets, warnings)
    else:
        raise CaptureError("not a pcap/pcapng file (bad magic number)")
    if len(pkts) >= max_packets:
        warnings.append(f"packet limit reached ({max_packets}); rest ignored")
    return pkts, warnings


def _read_pcap(data, end, res, max_packets, warnings):
    if len(data) < 24:
        raise CaptureError("truncated pcap header")
    snap, link = struct.unpack_from(end + "II", data, 16)
    link &= 0x0FFFFFFF
    if link not in (LINK_ETHERNET, LINK_SLL):
        warnings.append(f"unsupported link type {link}; no packets decoded")
        return []
    pkts, off, n = [], 24, 0
    while off + 16 <= len(data) and n < max_packets:
        sec, frac, incl, orig = struct.unpack_from(end + "IIII", data, off)
        off += 16
        if incl > MAX_RECORD or off + incl > len(data):
            warnings.append(f"corrupt or truncated record after packet {n}; stopped reading")
            break
        n += 1
        pkts.append(RawPacket(n, sec + frac * res, data[off:off + incl], link, orig))
        off += incl
    return pkts


def _read_pcapng(data, max_packets, warnings):
    pkts, off, n, end = [], 0, 0, "<"
    ifaces = []  # (linktype, ts_resolution)
    while off + 12 <= len(data) and n < max_packets:
        if data[off:off + 4] == b"\x0a\x0d\x0d\x0a":
            bom = data[off + 8:off + 12]
            end = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            ifaces = []
        btype, blen = struct.unpack_from(end + "II", data, off)
        if blen < 12 or blen % 4 or off + blen > len(data):
            warnings.append("corrupt or truncated block; stopped reading")
            break
        body = data[off + 8:off + blen - 4]
        if btype == 1 and len(body) >= 8:  # Interface Description
            link = struct.unpack_from(end + "H", body, 0)[0]
            ifaces.append((link, _tsresol(body[8:], end)))
        elif btype == 6 and len(body) >= 20:  # Enhanced Packet
            iid, hi, lo, cap, orig = struct.unpack_from(end + "IIIII", body, 0)
            if iid < len(ifaces) and cap <= MAX_RECORD and 20 + cap <= len(body):
                link, res = ifaces[iid]
                if link in (LINK_ETHERNET, LINK_SLL):
                    n += 1
                    pkts.append(RawPacket(n, ((hi << 32) | lo) * res, body[20:20 + cap], link, orig))
        elif btype == 3 and len(body) >= 4 and ifaces:  # Simple Packet
            orig = struct.unpack_from(end + "I", body, 0)[0]
            link = ifaces[0][0]
            if link in (LINK_ETHERNET, LINK_SLL):
                n += 1
                pkts.append(RawPacket(n, 0.0, body[4:4 + min(orig, len(body) - 4)], link, orig))
        off += blen
    return pkts


def _tsresol(opts, end):
    off = 0
    while off + 4 <= len(opts):
        code, ln = struct.unpack_from(end + "HH", opts, off)
        if code == 0:
            break
        if code == 9 and ln >= 1 and off + 5 <= len(opts):
            v = opts[off + 4]
            return 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
        off += 4 + ((ln + 3) & ~3)
    return 1e-6
