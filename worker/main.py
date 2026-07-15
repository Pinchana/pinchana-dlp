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
import unicodedata
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

QUALITY_HEIGHTS = {
    "best": None,
    "8k": 4320,
    "4k": 2160,
    "1440p": 1440,
    "1080p": 1080,
    "720p": 720,
    "480p": 480,
    "360p": 360,
    "240p": 240,
    "144p": 144,
    "audio": None,
}
CODEC_FILTERS = {
    "auto": None,
    "h264": ("avc1", "mp4a"),
    "av1": ("av01", "opus"),
    "vp9": ("vp9", "opus"),
}
CONTAINERS = {"auto", "mp4", "webm", "mkv"}
AUDIO_FORMATS = {"best", "mp3", "ogg", "wav", "opus"}
AUDIO_BITRATES = {"320", "256", "128", "96", "64", "8"}
YOUTUBE_DUB_LANGUAGES = {
    "af", "az", "id", "ms", "bs", "ca", "cs", "da", "de", "et", "en-IN", "en-GB", "en",
    "es", "es-419", "es-US", "eu", "fil", "fr", "fr-CA", "gl", "hr", "zu", "is", "it", "sw",
    "lv", "lt", "hu", "nl", "no", "uz", "pl", "pt-PT", "pt", "ro", "sq", "sk", "sl",
    "sr-Latn", "fi", "sv", "vi", "tr", "be", "bg", "ky", "kk", "mk", "mn", "ru", "sr", "uk",
    "el", "hy", "iw", "ur", "ar", "fa", "ne", "mr", "hi", "as", "bn", "pa", "gu", "or", "ta",
    "te", "kn", "ml", "si", "th", "lo", "my", "ka", "am", "km", "zh-CN", "zh-TW", "zh-HK",
    "ja", "ko",
}
AUDIO_FORMAT_ARGUMENTS = {"mp3": "mp3", "ogg": "vorbis", "wav": "wav", "opus": "opus"}
AUDIO_MIME_TYPES = {
    ".aac": "audio/aac",
    ".flac": "audio/flac",
    ".m4a": "audio/mp4",
    ".mp3": "audio/mpeg",
    ".ogg": "audio/ogg",
    ".opus": "audio/opus",
    ".wav": "audio/wav",
    ".webm": "audio/webm",
}
FILENAME_STYLES = {"classic", "basic", "pretty", "nerdy"}
BRAND_MARK = "[pinchana.cc]"
MAX_FILENAME_BYTES = 240


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


def clean_filename_part(value: object, fallback: str = "") -> str:
    text = unicodedata.normalize("NFKC", str(value or ""))
    text = re.sub(r'[<>:"/\\|?*\x00-\x1f\x7f]', " ", text)
    text = re.sub(r"\s+", " ", text).strip(" .")
    return text or fallback


def machine_filename_part(value: object, fallback: str = "") -> str:
    text = clean_filename_part(value, fallback)
    text = re.sub(r"[^\w.-]+", "_", text, flags=re.UNICODE).strip("._-")
    return text or fallback


def codec_label(metadata: dict[str, object], payload: dict[str, object], *, machine: bool = False) -> str:
    raw = str(metadata.get("vcodec") or payload.get("codec") or "").lower()
    if raw in {"", "none", "auto", "na"}:
        return ""
    if raw.startswith(("avc", "h264")):
        return "h264" if machine else "H.264"
    if raw.startswith(("av01", "av1")):
        return "av1" if machine else "AV1"
    if raw.startswith(("vp09", "vp9")):
        return "vp9" if machine else "VP9"
    return machine_filename_part(raw) if machine else clean_filename_part(raw)


def truncate_utf8(value: str, maximum: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= maximum:
        return value
    return encoded[:maximum].decode("utf-8", errors="ignore").rstrip(" ._-")


def branded_filename(base: str, extension: str, *, machine: bool = False) -> str:
    extension = machine_filename_part(extension.lower(), "bin")
    separator = "_" if machine else " "
    suffix = f"{separator}{BRAND_MARK}.{extension}"
    prefix = clean_filename_part(base, "media")
    maximum = MAX_FILENAME_BYTES - len(suffix.encode("utf-8"))
    prefix = truncate_utf8(prefix, maximum) or "media"
    return f"{prefix}{suffix}"


def build_filename(metadata: dict[str, object], payload: dict[str, object], extension: str) -> str:
    style = str(payload.get("filenameStyle", "pretty"))
    if style not in FILENAME_STYLES:
        raise ValueError("unsupported filename style")
    video_id = clean_filename_part(metadata.get("id"), "video")
    title = clean_filename_part(metadata.get("title"), video_id)
    author = clean_filename_part(
        metadata.get("uploader") or metadata.get("channel") or metadata.get("artist")
    )
    human = " - ".join(part for part in (title, author) if part)
    audio_only = str(payload.get("quality", "best")) == "audio"
    height = metadata.get("height")
    quality = f"{int(height)}p" if isinstance(height, (int, float)) and height > 0 else ""
    resolution = clean_filename_part(metadata.get("resolution"))
    if not resolution and quality:
        resolution = quality

    if style == "classic":
        parts = ["youtube", machine_filename_part(video_id, "video")]
        if audio_only:
            parts.append("audio")
        else:
            if resolution:
                parts.append(machine_filename_part(resolution))
            codec = codec_label(metadata, payload, machine=True)
            if codec:
                parts.append(codec)
        return branded_filename("_".join(parts), extension, machine=True)

    if style == "basic":
        return branded_filename(human, extension)

    details: list[str] = []
    if not audio_only:
        if quality:
            details.append(quality)
        codec = codec_label(metadata, payload)
        if codec:
            details.append(codec)
    details.append("youtube")
    if style == "nerdy":
        details.append(video_id)
    return branded_filename(f"{human} ({', '.join(details)})", extension)


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


def audio_candidates(dub_language: str, audio_codec: str | None = None) -> list[str]:
    if dub_language != "original" and dub_language not in YOUTUBE_DUB_LANGUAGES:
        raise ValueError("unsupported YouTube dub language")
    filters: list[str] = []
    if dub_language != "original":
        filters.append(f"[language^={dub_language}]")
    codec_filter = f"[acodec^={audio_codec}]" if audio_codec else ""
    candidates: list[str] = []
    if filters:
        if codec_filter:
            candidates.append(f"bestaudio{''.join(filters)}{codec_filter}")
        candidates.append(f"bestaudio{''.join(filters)}")
    if codec_filter:
        candidates.append(f"bestaudio{codec_filter}")
    candidates.append("bestaudio")
    return candidates


def format_selector(quality: str, codec: str, dub_language: str = "original") -> str:
    if quality not in QUALITY_HEIGHTS:
        raise ValueError("unsupported quality")
    if codec not in CODEC_FILTERS:
        raise ValueError("unsupported codec")
    preferred = CODEC_FILTERS[codec]
    preferred_audio_codec = preferred[1] if preferred else None
    audios = audio_candidates(dub_language, preferred_audio_codec)
    if quality == "audio":
        return "/".join([*audios, "best"])
    height = QUALITY_HEIGHTS[quality]
    height_filter = f"[height<={height}]" if height else ""
    video = f"bestvideo{height_filter}"
    combined = f"best{height_filter}"
    if preferred is None:
        return "/".join([*(f"{video}+{audio}" for audio in audios), combined])
    video_codec, _audio_codec = preferred
    preferred_video = f"{video}[vcodec^={video_codec}]"
    return "/".join([
        *(f"{candidate_video}+{audio}" for candidate_video in (preferred_video, video) for audio in audios),
        combined,
    ])


def output_container(codec: str, container: str, quality: str) -> str | None:
    if container not in CONTAINERS:
        raise ValueError("unsupported container")
    if quality == "audio":
        return None
    if container != "auto":
        return container
    if codec == "h264":
        return "mp4"
    if codec in {"av1", "vp9"}:
        return "webm"
    return None


def build_command(payload: dict[str, object], cookies_path: Path | None) -> list[str]:
    quality = str(payload.get("quality", "best"))
    codec = str(payload.get("codec", "auto"))
    container = str(payload.get("container", "auto"))
    audio_format = str(payload.get("audioFormat", "best"))
    audio_bitrate = str(payload.get("audioBitrate", "128"))
    dub_language = str(payload.get("dubLanguage", "original"))
    subtitle_language = str(payload.get("subtitleLanguage", "none"))
    if audio_format not in AUDIO_FORMATS:
        raise ValueError("unsupported audio format")
    if audio_bitrate not in AUDIO_BITRATES:
        raise ValueError("unsupported audio bitrate")
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
        format_selector(quality, codec, dub_language),
        "--output",
        str(OUTPUT_DIR / "media.%(ext)s"),
        "--print-to-file",
        "after_move:%()j",
        str(OUTPUT_DIR / ".metadata.json"),
    ]
    selected_container = output_container(codec, container, quality)
    if selected_container:
        command.extend(["--merge-output-format", selected_container, "--remux-video", selected_container])
    if payload.get("preferBetterAudio") is True:
        command.extend(["--format-sort", "abr,asr,channels"])
    if quality == "audio" and audio_format != "best":
        command.extend(["--extract-audio", "--audio-format", AUDIO_FORMAT_ARGUMENTS[audio_format]])
        if audio_format in {"mp3", "ogg", "opus"}:
            command.extend(["--audio-quality", f"{audio_bitrate}K"])
    if quality != "audio" and subtitle_language != "none":
        if subtitle_language not in YOUTUBE_DUB_LANGUAGES:
            raise ValueError("unsupported subtitle language")
        command.extend([
            "--write-subs",
            "--write-auto-subs",
            "--sub-langs",
            subtitle_language,
            "--embed-subs",
            "--compat-options",
            "no-keep-subs",
        ])
    if cookies_path:
        command.extend(["--cookies", str(cookies_path)])
    if PROXY_URL:
        command.extend(["--proxy", PROXY_URL])
    command.append(str(payload["url"]))
    return command


def execute(payload: dict[str, object], cookies_path: Path | None) -> Path:
    command = build_command(payload, cookies_path)
    metadata_path = OUTPUT_DIR / ".metadata.json"
    metadata_path.unlink(missing_ok=True)

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
    metadata: dict[str, object] = {}
    if metadata_path.is_file():
        try:
            lines = [line for line in metadata_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            if lines:
                parsed = json.loads(lines[-1])
                if isinstance(parsed, dict):
                    metadata = parsed
        finally:
            metadata_path.unlink(missing_ok=True)
    files = [path for path in OUTPUT_DIR.iterdir() if path.is_file()]
    if len(files) != 1:
        raise RuntimeError("Download produced an unexpected number of files")
    if files[0].stat().st_size > MAX_OUTPUT_BYTES:
        raise ValueError("Download exceeded the output size limit")
    output = files[0]
    final_name = build_filename(metadata, payload, output.suffix.lstrip("."))
    final_output = output.with_name(final_name)
    output.replace(final_output)
    return final_output


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
            "mime": AUDIO_MIME_TYPES.get(output.suffix.lower(), "application/octet-stream")
            if payload.get("quality") == "audio" else "application/octet-stream",
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
