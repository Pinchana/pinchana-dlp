"""Ephemeral protocol-v2 DLP worker."""

from __future__ import annotations

import base64
import json
import os
import re
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTOCOL_VERSION = 2
JOB_ID = os.environ.get("JOB_ID", "")
JOB_TOKEN = os.environ.get("JOB_TOKEN", "")
API_URL = os.environ.get("DLP_API_URL", "http://dlp-api:8080").rstrip("/")
OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", "/output"))
COOKIE_DIR = Path("/run/cookies")
PROXY_URL = os.environ.get("VPN_PROXY_URL", "")
EXECUTION_TIMEOUT = int(os.environ.get("EXECUTION_TIMEOUT_SECONDS", "900"))
MAX_OUTPUT_BYTES = int(os.environ.get("MAX_OUTPUT_BYTES", str(2 * 1024 * 1024 * 1024)))

QUALITY_FORMATS = {
    "best": "bv*+ba/b",
    "1080p": "bestvideo[height<=1080]+bestaudio/best[height<=1080]",
    "720p": "bestvideo[height<=720]+bestaudio/best[height<=720]",
    "480p": "bestvideo[height<=480]+bestaudio/best[height<=480]",
    "360p": "bestvideo[height<=360]+bestaudio/best[height<=360]",
    "audio": "bestaudio/best",
}


def b64d(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def aad(job_id: str, key_id: str) -> bytes:
    return f"pinchana-dlp:v2:{job_id}:{key_id}".encode("utf-8")


def derive_aes_key(shared_secret: bytes, salt: bytes, job_id: str, key_id: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=f"pinchana-dlp/cookies/v2/{job_id}/{key_id}".encode("utf-8"),
    ).derive(shared_secret)


def decrypt_cookies(
    envelope: dict[str, object],
    worker_private: x25519.X25519PrivateKey,
    job_id: str,
    expected_key_id: str,
) -> bytearray:
    if envelope.get("version") != PROTOCOL_VERSION or envelope.get("keyId") != expected_key_id:
        raise ValueError("cookie envelope protocol or key mismatch")
    client_public = x25519.X25519PublicKey.from_public_bytes(b64d(str(envelope["clientPubKey"])))
    salt = b64d(str(envelope["salt"]))
    iv = b64d(str(envelope["iv"]))
    if len(salt) != 32 or len(iv) != 12:
        raise ValueError("invalid cookie envelope parameters")
    key = derive_aes_key(worker_private.exchange(client_public), salt, job_id, expected_key_id)
    plaintext = AESGCM(key).decrypt(iv, b64d(str(envelope["ciphertext"])), aad(job_id, expected_key_id))
    return bytearray(plaintext)


def validate_netscape_cookies(value: bytes) -> None:
    text = value.decode("utf-8", errors="strict")
    if len(value) > 256 * 1024 or "\x00" in text:
        raise ValueError("cookie file is invalid or too large")
    lines = [
        line
        for line in text.splitlines()
        if line and (not line.startswith("#") or line.startswith("#HttpOnly_"))
    ]
    if not lines:
        raise ValueError("cookie file contains no cookies")
    for line in lines:
        fields = line.split("\t")
        if len(fields) != 7 or fields[1] not in {"TRUE", "FALSE"} or fields[3] not in {"TRUE", "FALSE"}:
            raise ValueError("cookie file is not Netscape format")
        int(fields[4])


def sanitize_error(value: str) -> str:
    value = re.sub(r"(?i)(cookie|authorization):?\s+\S+", r"\1: <redacted>", value)
    value = re.sub(r"https?://\S+", "<url>", value)
    value = re.sub(r"/run/cookies/\S+", "/run/cookies/<redacted>", value)
    value = re.sub(r"/output/\S+", "/output/<file>", value)
    return value[:500]


session = requests.Session()
session.headers["x-job-token"] = JOB_TOKEN


def call(method: str, path: str, payload: dict[str, object] | None = None, *, allow_404: bool = False):
    response = session.request(method, f"{API_URL}{path}", json=payload, timeout=10)
    if allow_404 and response.status_code == 404:
        return None
    response.raise_for_status()
    return response.json()


def progress(stage: str, percent: float) -> None:
    call("POST", f"/internal/jobs/{JOB_ID}/progress", {"stage": stage, "progress": percent})


def output_size() -> int:
    return sum(path.stat().st_size for path in OUTPUT_DIR.iterdir() if path.is_file())


def execute(payload: dict[str, object], cookies_path: Path | None) -> Path:
    quality = str(payload.get("quality", "best"))
    if quality not in QUALITY_FORMATS:
        raise ValueError("unsupported quality")
    command = [
        sys.executable,
        "-m",
        "yt_dlp",
        "--no-playlist",
        "--newline",
        "--no-colors",
        "--no-write-thumbnail",
        "--no-write-info-json",
        "--restrict-filenames",
        "--js-runtimes",
        "deno:/usr/local/bin/deno",
        "--format",
        QUALITY_FORMATS[quality],
        "--output",
        str(OUTPUT_DIR / "media.%(ext)s"),
    ]
    if cookies_path:
        command.extend(["--cookies", str(cookies_path)])
    if PROXY_URL:
        command.extend(["--proxy", PROXY_URL])
    command.append(str(payload["url"]))

    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        start_new_session=True,
    )
    assert proc.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ)
    progress_pattern = re.compile(r"\[download\]\s+(\d+(?:\.\d+)?)%")
    deadline = time.monotonic() + EXECUTION_TIMEOUT
    last_report = 0.0
    last_lines: list[str] = []
    try:
        while proc.poll() is None:
            if time.monotonic() >= deadline:
                raise TimeoutError("Download exceeded the execution time limit")
            if output_size() > MAX_OUTPUT_BYTES:
                raise ValueError("Download exceeded the output size limit")
            for key, _ in selector.select(timeout=0.5):
                line = key.fileobj.readline()
                if not line:
                    continue
                clean = sanitize_error(line.strip())
                last_lines = (last_lines + [clean])[-4:]
                match = progress_pattern.search(line)
                if match and time.monotonic() - last_report >= 2:
                    progress("downloading", min(float(match.group(1)), 99))
                    last_report = time.monotonic()
    except Exception:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=5)
        raise
    if proc.returncode:
        raise RuntimeError(f"yt-dlp failed ({proc.returncode}): {' | '.join(last_lines)}")
    files = [path for path in OUTPUT_DIR.iterdir() if path.is_file()]
    if len(files) != 1:
        raise RuntimeError("Download produced an unexpected number of files")
    if files[0].stat().st_size > MAX_OUTPUT_BYTES:
        raise ValueError("Download exceeded the output size limit")
    return files[0]


def run() -> None:
    if not JOB_ID or not JOB_TOKEN:
        raise RuntimeError("Missing job identity")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    COOKIE_DIR.mkdir(parents=True, exist_ok=True)
    worker_private = x25519.X25519PrivateKey.generate()
    key_id = f"wk-{os.urandom(16).hex()}"
    key_expires = int(time.time()) + 300
    call("POST", f"/internal/jobs/{JOB_ID}/register", {
        "keyId": key_id,
        "workerPubKey": b64e(worker_private.public_key().public_bytes_raw()),
        "expiresAt": key_expires,
    })

    payload = None
    deadline = time.monotonic() + 75
    while time.monotonic() < deadline:
        payload = call("GET", f"/internal/jobs/{JOB_ID}/payload", allow_404=True)
        if payload is not None:
            break
        time.sleep(0.5)
    if payload is None:
        raise TimeoutError("Job was not submitted before allocation expired")

    cookies_path: Path | None = None
    plaintext: bytearray | None = None
    try:
        envelope = payload.get("cookiesEnc")
        if envelope is not None:
            progress("decrypting", 0)
            plaintext = decrypt_cookies(envelope, worker_private, JOB_ID, key_id)
            validate_netscape_cookies(bytes(plaintext))
            cookies_path = COOKIE_DIR / "cookies.txt"
            with cookies_path.open("wb") as handle:
                handle.write(plaintext)
            cookies_path.chmod(0o600)
        progress("starting", 0)
        output = execute(payload, cookies_path)
        progress("finalizing", 100)
        call("POST", f"/internal/jobs/{JOB_ID}/complete", {
            "filename": output.name,
            "size": output.stat().st_size,
            "mime": "audio/mpeg" if payload.get("quality") == "audio" else "application/octet-stream",
        })
    finally:
        if plaintext is not None:
            plaintext[:] = b"\0" * len(plaintext)
        if cookies_path:
            cookies_path.unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        run()
    except Exception as exc:
        try:
            call("POST", f"/internal/jobs/{JOB_ID}/fail", {"error": sanitize_error(str(exc)) or "Worker failed"})
        except Exception:
            pass
        raise SystemExit(1)
