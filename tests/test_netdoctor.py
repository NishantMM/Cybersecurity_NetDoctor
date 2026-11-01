import os
import random
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from netdoctor.analyze import analyze_file          # noqa: E402
from netdoctor.pcap import CaptureError, read_capture  # noqa: E402
from netdoctor.report import to_html                # noqa: E402

S = lambda n: os.path.join(ROOT, "samples", n)


def codes(name):
    return {f.code for f in analyze_file(S(name))["findings"]}


class Detection(unittest.TestCase):
    def test_normal_traffic_is_clean(self):
        self.assertEqual(codes("01_normal.pcap"), set())      # busy browser must not look like a scan

    def test_faults_only(self):
        r = analyze_file(S("02_outage_faults.pcap"))
        self.assertEqual(r["stats"]["attacks"], 0)
        for c in ("tcp_retransmissions", "unreachable_server", "dns_timeouts", "dns_failures",
                  "tcp_resets", "mtu_mismatch", "slow_handshake"):
            self.assertIn(c, {f.code for f in r["findings"]})

    def test_attacks(self):
        self.assertIn("arp_spoofing", codes("03_arp_spoofing.pcap"))
        self.assertIn("port_scan", codes("04_port_scan.pcap"))
        self.assertIn("dns_hijack", codes("05_dns_hijack.pcap"))
        self.assertIn("rogue_dhcp", codes("06_rogue_dhcp.pcap"))

    def test_duplicate_ip_is_a_fault_not_an_attack(self):
        r = analyze_file(S("07_duplicate_ip.pcap"))
        self.assertEqual([f.code for f in r["findings"]], ["duplicate_ip"])
        self.assertEqual(r["stats"]["attacks"], 0)

    def test_side_effect_is_linked_to_attack(self):
        r = analyze_file(S("03_arp_spoofing.pcap"))
        self.assertTrue(any(f.details.get("caused_by") == "arp_spoofing" for f in r["findings"]))


class Robustness(unittest.TestCase):
    def tmp(self, data):
        fd, p = tempfile.mkstemp()
        os.write(fd, data)
        os.close(fd)
        self.addCleanup(os.unlink, p)
        return p

    def test_bad_inputs_raise_clean_errors(self):
        for data in (b"", b"hello world", b"\xd4\xc3\xb2\xa1"):
            with self.assertRaises(CaptureError):
                read_capture(self.tmp(data))

    def test_corrupt_tail_gives_warning(self):
        r = analyze_file(S("malformed.pcap"))
        self.assertTrue(r["warnings"])

    def test_random_mutation_never_crashes(self):
        base = open(S("08_mixed_incident.pcap"), "rb").read()
        rnd = random.Random(1)
        for _ in range(60):
            b = bytearray(base)
            for _ in range(rnd.randint(1, 200)):
                b[rnd.randrange(len(b))] = rnd.randrange(256)
            if rnd.random() < .3:
                b = b[:rnd.randrange(24, len(b))]
            try:
                analyze_file(self.tmp(bytes(b)))
            except CaptureError:
                pass

    def test_size_and_packet_limits(self):
        with self.assertRaises(CaptureError):
            read_capture(S("08_mixed_incident.pcap"), max_bytes=100)
        pk, w = read_capture(S("08_mixed_incident.pcap"), max_packets=10)
        self.assertEqual(len(pk), 10)
        self.assertTrue(w)

    def test_html_escapes_attacker_controlled_names(self):
        r = analyze_file(S("05_dns_hijack.pcap"))
        for p in r["packets"]:
            if p.dns:
                p.dns["qname"] = "<script>alert(1)</script>"
        for f in r["findings"]:
            f.summary += "<script>alert(1)</script>"
        self.assertNotIn("<script>alert", to_html(r))

    def test_cli_exit_codes(self):
        run = lambda f: subprocess.run([sys.executable, "-m", "netdoctor", S(f)], cwd=ROOT, capture_output=True).returncode
        self.assertEqual(run("01_normal.pcap"), 0)
        self.assertEqual(run("04_port_scan.pcap"), 1)
        self.assertEqual(subprocess.run([sys.executable, "-m", "netdoctor", "/nonexistent"], cwd=ROOT, capture_output=True).returncode, 2)


class Web(unittest.TestCase):
    def test_upload(self):
        try:
            from netdoctor.web import create_app
        except ImportError:
            self.skipTest("Flask not installed")
        c = create_app(max_mb=1).test_client()
        self.assertEqual(c.get("/").status_code, 200)
        with open(S("04_port_scan.pcap"), "rb") as f:
            r = c.post("/", data={"capture": (f, "x.pcap")}, content_type="multipart/form-data")
        self.assertIn(b"Port scan", r.data)
        r = c.post("/", data={"capture": (__import__("io").BytesIO(b"junk"), "x.pcap")}, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main()
