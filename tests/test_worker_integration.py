from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest

import worker.main as worker


COOKIE_VALUE = "COOKIE_MARKER_NEVER_PERSIST"
MEDIA = b"local-cookie-protected-media-fixture"


class ProtectedMediaHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        if self.headers.get("Cookie") != f"fixture={COOKIE_VALUE}":
            self.send_response(403)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "video/mp4")
        self.send_header("Content-Length", str(len(MEDIA)))
        self.end_headers()
        self.wfile.write(MEDIA)

    def log_message(self, _format, *_args):
        return


@pytest.fixture
def protected_media_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), ProtectedMediaHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/media.mp4"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_worker_downloads_local_cookie_protected_fixture(monkeypatch, tmp_path, protected_media_url):
    output = tmp_path / "output"
    output.mkdir()
    cookie_file = tmp_path / "cookies.txt"
    cookie_file.write_text(
        f"# Netscape HTTP Cookie File\n127.0.0.1\tFALSE\t/\tFALSE\t0\tfixture\t{COOKIE_VALUE}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(worker, "OUTPUT_DIR", output)
    monkeypatch.setattr(worker, "PROXY_URL", "")
    monkeypatch.setattr(worker, "EXECUTION_TIMEOUT", 30)
    monkeypatch.setattr(worker, "MAX_OUTPUT_BYTES", 1024 * 1024)
    monkeypatch.setattr(worker, "progress", lambda *_args: None)

    downloaded = worker.execute({"url": protected_media_url, "quality": "best"}, cookie_file)

    assert downloaded.read_bytes() == MEDIA
    assert COOKIE_VALUE not in downloaded.name


def test_run_removes_plaintext_cookie_file_and_wipes_buffer(monkeypatch, tmp_path):
    cookie_dir = tmp_path / "cookies"
    output_dir = tmp_path / "output"
    plaintext = bytearray(
        f"# Netscape HTTP Cookie File\n.youtube.com\tTRUE\t/\tTRUE\t0\tSID\t{COOKIE_VALUE}\n".encode()
    )
    captured = plaintext[:]
    payload_reads = 0

    def fake_call(method, path, payload=None, **_kwargs):
        nonlocal payload_reads
        if method == "GET" and path.endswith("/payload"):
            payload_reads += 1
            return {"url": "https://youtube.com/watch?v=abcdefghijk", "quality": "best", "cookiesEnc": {"version": 2}}
        return {"ok": True}

    def fake_execute(_payload, cookies_path: Path | None):
        assert cookies_path is not None
        assert COOKIE_VALUE.encode() in cookies_path.read_bytes()
        output = output_dir / "media.mp4"
        output.write_bytes(MEDIA)
        return output

    monkeypatch.setattr(worker, "JOB_ID", "12345678-1234-4234-9234-123456789abc")
    monkeypatch.setattr(worker, "JOB_TOKEN", "per-job-token")
    monkeypatch.setattr(worker, "COOKIE_DIR", cookie_dir)
    monkeypatch.setattr(worker, "OUTPUT_DIR", output_dir)
    monkeypatch.setattr(worker, "call", fake_call)
    monkeypatch.setattr(worker, "decrypt_cookies", lambda *_args: plaintext)
    monkeypatch.setattr(worker, "execute", fake_execute)

    worker.run()

    assert payload_reads == 1
    assert not (cookie_dir / "cookies.txt").exists()
    assert plaintext == bytearray(len(captured))
