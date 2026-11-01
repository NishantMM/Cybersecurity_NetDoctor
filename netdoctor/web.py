"""Tiny local web dashboard. Uploads are size-limited, stored only in a
temporary file under a random name (never the client's filename) and deleted
straight away. Output is HTML-escaped and served with a strict CSP."""
import html
import os
import tempfile

from flask import Flask, request

from .analyze import analyze_file
from .pcap import CaptureError
from .report import to_html

FORM = """<!doctype html><meta charset=utf-8><title>NetDoctor</title>
<body style="font:16px system-ui;max-width:640px;margin:3rem auto"><h1>NetDoctor</h1>
<p>Upload a .pcap or .pcapng. The file is analysed locally and deleted immediately.</p>
<form method=post enctype=multipart/form-data><input type=file name=capture required>
<button>Analyse</button></form>%s</body>"""


def create_app(max_mb=50):
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = max_mb * 1024 * 1024

    @app.after_request
    def headers(r):
        r.headers["X-Content-Type-Options"] = "nosniff"
        r.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'"
        return r

    @app.route("/", methods=["GET", "POST"])
    def index():
        if request.method == "GET":
            return FORM % ""
        f = request.files.get("capture")
        if not f:
            return FORM % "<p>No file received.</p>", 400
        fd, path = tempfile.mkstemp(suffix=".cap")
        try:
            with os.fdopen(fd, "wb") as out:
                f.save(out)
            return to_html(analyze_file(path), "uploaded capture")
        except CaptureError as e:
            return FORM % f"<p>Could not read that file: {html.escape(str(e)[:100])}</p>", 400
        finally:
            os.unlink(path)

    @app.errorhandler(413)
    def too_big(_):
        return FORM % f"<p>File too large (limit {max_mb} MB).</p>", 413

    return app
