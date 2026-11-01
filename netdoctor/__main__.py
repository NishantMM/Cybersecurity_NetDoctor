import argparse
import os
import sys

from . import __version__
from .analyze import analyze_file
from .pcap import CaptureError
from .report import to_html, to_json, to_text


def main(argv=None):
    ap = argparse.ArgumentParser(prog="netdoctor",
                                 description="Diagnose faults and attacks in a packet capture (.pcap/.pcapng).")
    ap.add_argument("capture", nargs="?", help="capture file to analyse")
    ap.add_argument("--format", choices=["text", "json", "html"], default="text")
    ap.add_argument("-o", "--output", help="write the report to this file instead of stdout")
    ap.add_argument("--serve", action="store_true", help="start the local web dashboard (needs Flask)")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(argv)
    if a.serve:
        from .web import create_app
        create_app().run(host="127.0.0.1", port=a.port)   # localhost only on purpose
        return 0
    if not a.capture:
        ap.error("give a capture file or use --serve")
    try:
        res = analyze_file(a.capture)
    except CaptureError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    name = os.path.basename(a.capture)
    out = {"text": to_text, "json": lambda r, n: to_json(r), "html": to_html}[a.format](res, name)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"wrote {a.output}")
    else:
        print(out)
    return 1 if res["stats"]["attacks"] else 0   # non-zero exit when an attack is found (handy for scripts)


if __name__ == "__main__":
    sys.exit(main())
