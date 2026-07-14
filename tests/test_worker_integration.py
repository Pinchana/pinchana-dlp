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


def test_worker_builds_fixed_codec_and_container_selectors(monkeypatch, tmp_path):
    monkeypatch.setattr(worker, "OUTPUT_DIR", tmp_path)
    monkeypatch.setattr(worker, "PROXY_URL", "http://vpn:8888")

    command = worker.build_command(
        {
            "url": "https://youtube.com/watch?v=abcdefghijk",
            "quality": "4k",
            "codec": "h264",
            "container": "mp4",
            "dubLanguage": "fr",
        },
        Path("/run/cookies/cookies.txt"),
    )

    selector = command[command.index("--format") + 1]
    assert "height<=2160" in selector
    assert "vcodec^=avc1" in selector
    assert "acodec^=mp4a" in selector
    assert "language^=fr" in selector
    assert command[command.index("--merge-output-format") + 1] == "mp4"
    assert command[command.index("--remux-video") + 1] == "mp4"
    assert command[command.index("--proxy") + 1] == "http://vpn:8888"
    assert command[-1] == "https://youtube.com/watch?v=abcdefghijk"


def test_auto_container_tracks_preferred_codec():
    assert worker.output_container("h264", "auto", "1080p") == "mp4"
    assert worker.output_container("av1", "auto", "4k") == "webm"
    assert worker.output_container("vp9", "auto", "4k") == "webm"
    assert worker.output_container("auto", "auto", "best") is None
    assert worker.output_container("h264", "auto", "audio") is None


@pytest.mark.parametrize(
    ("audio_format", "expected_format", "uses_bitrate"),
    [("mp3", "mp3", True), ("ogg", "vorbis", True), ("opus", "opus", True), ("wav", "wav", False)],
)
def test_audio_conversion_options(monkeypatch, tmp_path, audio_format, expected_format, uses_bitrate):
    monkeypatch.setattr(worker, "OUTPUT_DIR", tmp_path)
    monkeypatch.setattr(worker, "PROXY_URL", "")
    command = worker.build_command({
        "url": "https://youtube.com/watch?v=abcdefghijk",
        "quality": "audio",
        "audioFormat": audio_format,
        "audioBitrate": "256",
        "preferBetterAudio": True,
        "dubLanguage": "de",
    }, None)
    selector = command[command.index("--format") + 1]
    assert "language^=de" in selector
    assert command[command.index("--audio-format") + 1] == expected_format
    assert ("--audio-quality" in command) is uses_bitrate
    if uses_bitrate:
        assert command[command.index("--audio-quality") + 1] == "256K"
    assert command[command.index("--format-sort") + 1] == "abr,asr,channels"


def test_best_audio_keeps_source_without_conversion(monkeypatch, tmp_path):
    monkeypatch.setattr(worker, "OUTPUT_DIR", tmp_path)
    monkeypatch.setattr(worker, "PROXY_URL", "")
    command = worker.build_command({
        "url": "https://youtu.be/abcdefghijk",
        "quality": "audio",
        "audioFormat": "best",
        "dubLanguage": "original",
    }, None)
    assert "--extract-audio" not in command
    assert "--audio-quality" not in command


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
