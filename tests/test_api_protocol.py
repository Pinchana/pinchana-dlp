import base64
import json
import time

import fakeredis
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError

import api.main as dlp


OWNER_A = "owner-a"
OWNER_B = "owner-b"
TOKEN = "g" * 32


@pytest.fixture(autouse=True)
def fake_store(monkeypatch, tmp_path):
    store = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(dlp, "r", store)
    monkeypatch.setattr(dlp, "GATEWAY_SERVICE_TOKEN", TOKEN)
    monkeypatch.setattr(dlp, "JOBS_DIR", tmp_path)
    monkeypatch.setattr(dlp, "RATE_LIMIT_PER_MINUTE", 2)
    monkeypatch.setattr(dlp, "DLP_DOH_URL", "https://resolver.example/dns-query")
    monkeypatch.setattr(dlp, "DLP_DOH_PROXY_URL", "http://vpn:8888")
    return store


def context(owner=OWNER_A):
    return dlp.GatewayContext(owner=dlp._digest(owner))


def record(store, job_id="12345678-1234-4234-9234-123456789abc", status="ALLOCATED", owner=OWNER_A, expires=None):
    expires = expires or int(time.time()) + 600
    data = {
        "jobId": job_id,
        "ownerDigest": dlp._digest(owner),
        "credentialDigest": dlp._digest("job-token"),
        "status": status,
        "createdAt": str(int(time.time())),
        "updatedAt": str(int(time.time())),
        "expiresAt": str(expires),
        "keyId": "wk-test-key",
        "workerPubKey": base64.b64encode(b"p" * 32).decode(),
        "keyExpiresAt": str(int(time.time()) + 300),
    }
    store.hset(dlp.job_key(job_id), mapping=data)
    store.expireat(dlp.job_key(job_id), expires)
    return job_id


def test_gateway_authentication_and_owner_derivation():
    assert dlp.require_gateway(TOKEN, OWNER_A).owner == dlp._digest(OWNER_A)
    with pytest.raises(HTTPException) as failure:
        dlp.require_gateway("wrong", OWNER_A)
    assert failure.value.status_code == 403


def test_runtime_configuration_rejects_placeholder_secrets(monkeypatch):
    monkeypatch.setattr(dlp, "GATEWAY_SERVICE_TOKEN", "dlp-disabled-change-me")
    with pytest.raises(RuntimeError, match="DLP_GATEWAY_TOKEN"):
        dlp.validate_runtime_config()


def test_runtime_configuration_accepts_production_bounds(monkeypatch):
    monkeypatch.setattr(dlp, "GATEWAY_SERVICE_TOKEN", "g" * 32)
    monkeypatch.setattr(dlp, "REDIS_URL", "redis://:a-real-random-password@redis:6379/0")
    dlp.validate_runtime_config()


def test_hostname_resolution_uses_doh_proxy(monkeypatch):
    payloads = {
        "A": {"Status": 0, "Answer": [{"type": 1, "data": "142.250.74.206"}]},
        "AAAA": {"Status": 0, "Answer": [{"type": 28, "data": "2a00:1450:4001:830::200e"}]},
    }
    requests = []

    class Response:
        def __init__(self, payload):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return json.dumps(self.payload).encode()

    class Opener:
        def open(self, request, timeout):
            requests.append((request.full_url, timeout))
            record_type = "AAAA" if "type=AAAA" in request.full_url else "A"
            return Response(payloads[record_type])

    monkeypatch.setattr(dlp.url_request, "build_opener", lambda *_args: Opener())

    assert dlp.resolve_hostname("youtube.com") == {"142.250.74.206", "2a00:1450:4001:830::200e"}
    assert len(requests) == 2


def test_private_doh_answer_is_rejected(monkeypatch):
    monkeypatch.setattr(dlp, "resolve_hostname", lambda _hostname: {"127.0.0.1"})
    with pytest.raises(HTTPException, match="Private network targets"):
        dlp.validate_public_url("https://example.com/video")


def test_owner_cannot_read_another_sessions_job(fake_store):
    job_id = record(fake_store)
    with pytest.raises(HTTPException) as failure:
        dlp.get_job(job_id, context(OWNER_B))
    assert failure.value.status_code == 404


def test_anonymous_submission_is_one_time_and_has_fixed_quality(fake_store, monkeypatch):
    job_id = record(fake_store)
    monkeypatch.setattr(dlp, "validate_public_url", lambda value: value)
    request = dlp.SubmitRequest(url="https://www.youtube.com/watch?v=abcdefghijk", quality="720p")
    assert dlp.submit_job(job_id, request, context())["status"] == "QUEUED"
    payload = fake_store.get(f"{dlp.job_key(job_id)}:payload")
    assert '"cookiesEnc": null' in payload
    assert "format" not in payload
    with pytest.raises(HTTPException) as replay:
        dlp.submit_job(job_id, request, context())
    assert replay.value.status_code == 409
    with pytest.raises(ValidationError):
        dlp.SubmitRequest(url=request.url, quality="custom-format")
    with pytest.raises(ValidationError):
        dlp.SubmitRequest(url=request.url, codec="raw-codec")
    with pytest.raises(ValidationError):
        dlp.SubmitRequest(url=request.url, container="avi")
    with pytest.raises(ValidationError):
        dlp.SubmitRequest(url=request.url, audioFormat="flac")
    with pytest.raises(ValidationError):
        dlp.SubmitRequest(url=request.url, audioBitrate="192")
    with pytest.raises(ValidationError):
        dlp.SubmitRequest(url=request.url, dubLanguage="not-a-language")
    with pytest.raises(ValidationError):
        dlp.SubmitRequest(url=request.url, filenameStyle="random")
    with pytest.raises(ValidationError):
        dlp.SubmitRequest(url=request.url, subtitleLanguage="not-a-language")


def test_health_advertises_naming_and_subtitle_capabilities():
    capabilities = dlp.health()["capabilities"]
    assert capabilities["filenameStyles"] == ["classic", "basic", "pretty", "nerdy"]
    assert "en" in capabilities["subtitleLanguages"]


def test_redis_payload_contains_ciphertext_but_not_plaintext_marker(fake_store, monkeypatch):
    job_id = record(fake_store)
    monkeypatch.setattr(dlp, "validate_public_url", lambda value: value)
    envelope = dlp.CookiesEnvelope(
        version=2,
        keyId="wk-test-key",
        clientPubKey=base64.b64encode(b"p" * 32).decode(),
        salt=base64.b64encode(b"s" * 32).decode(),
        iv=base64.b64encode(b"i" * 12).decode(),
        ciphertext=base64.b64encode(b"encrypted-cookie-marker").decode(),
    )
    dlp.submit_job(job_id, dlp.SubmitRequest(url="https://youtube.com/watch?v=abcdefghijk", cookiesEnc=envelope), context())
    persisted = fake_store.get(f"{dlp.job_key(job_id)}:payload")
    assert "COOKIE_MARKER_NEVER_PERSIST" not in persisted
    assert envelope.ciphertext in persisted


def test_expired_worker_key_rejects_submission(fake_store, monkeypatch):
    job_id = record(fake_store)
    fake_store.hset(dlp.job_key(job_id), "keyExpiresAt", int(time.time()) - 1)
    monkeypatch.setattr(dlp, "validate_public_url", lambda value: value)
    with pytest.raises(HTTPException) as failure:
        dlp.submit_job(job_id, dlp.SubmitRequest(url="https://youtube.com/watch?v=abcdefghijk"), context())
    assert failure.value.status_code == 410


@pytest.mark.parametrize("url", ["http://127.0.0.1/file", "http://[::1]/file", "http://localhost/file", "http://169.254.169.254/latest/meta-data"])
def test_ssrf_targets_are_rejected(url):
    with pytest.raises(HTTPException) as failure:
        dlp.validate_public_url(url)
    assert failure.value.status_code == 400


@pytest.mark.parametrize("url", [
    "https://example.com/video",
    "https://youtube.com.example.com/watch?v=abcdefghijk",
    "https://notyoutube.com/watch?v=abcdefghijk",
])
def test_dlp_rejects_non_youtube_hosts(url):
    with pytest.raises(HTTPException, match="YouTube URLs only"):
        dlp.validate_youtube_url(url)


@pytest.mark.parametrize("url", [
    "https://youtube.com/watch?v=abcdefghijk",
    "https://music.youtube.com/watch?v=abcdefghijk",
    "https://youtu.be/abcdefghijk",
])
def test_dlp_accepts_youtube_hosts(monkeypatch, url):
    monkeypatch.setattr(dlp, "validate_public_url", lambda value: value)
    assert dlp.validate_youtube_url(url) == url


def test_ciphertext_and_envelope_limits_are_enforced():
    common = {"version": 2, "keyId": "wk-test-key", "clientPubKey": base64.b64encode(b"p" * 32).decode(), "salt": base64.b64encode(b"s" * 32).decode(), "iv": base64.b64encode(b"i" * 12).decode()}
    with pytest.raises(ValidationError):
        dlp.CookiesEnvelope(**common, ciphertext=base64.b64encode(b"x" * (dlp.MAX_CIPHERTEXT_BYTES + 1)).decode())


def test_rate_limit_is_per_owner(fake_store):
    dlp.check_rate_limit(context().owner)
    dlp.check_rate_limit(context().owner)
    with pytest.raises(HTTPException) as failure:
        dlp.check_rate_limit(context().owner)
    assert failure.value.status_code == 429


def test_worker_credential_and_invalid_transition(fake_store):
    job_id = record(fake_store, status="RUNNING")
    with pytest.raises(HTTPException) as failure:
        dlp.require_worker(job_id, "wrong")
    assert failure.value.status_code == 403
    with pytest.raises(HTTPException) as transition:
        dlp.transition(job_id, {"ALLOCATED"}, "QUEUED")
    assert transition.value.status_code == 409


def test_file_requires_owner_and_ready_state(fake_store, tmp_path):
    job_id = record(fake_store, status="READY")
    output = tmp_path / job_id / "media.mp4"
    output.parent.mkdir()
    output.write_bytes(b"media")
    fake_store.hset(dlp.job_key(job_id), mapping={"filename": output.name, "mime": "video/mp4", "size": "5"})
    assert dlp.get_file(job_id, context()).path == output
    with pytest.raises(HTTPException):
        dlp.get_file(job_id, context(OWNER_B))


@pytest.mark.parametrize(
    ("range_header", "expected_status", "expected_body", "expected_content_range"),
    [
        ("bytes=1-3", 206, b"edi", "bytes 1-3/5"),
        ("bytes=-2", 206, b"ia", "bytes 3-4/5"),
        ("bytes=10-20", 416, b"", "*/5"),
    ],
)
def test_file_supports_private_byte_ranges(fake_store, tmp_path, range_header, expected_status, expected_body, expected_content_range):
    job_id = record(fake_store, status="READY")
    output = tmp_path / job_id / "media [pinchana.cc].mp4"
    output.parent.mkdir()
    output.write_bytes(b"media")
    fake_store.hset(dlp.job_key(job_id), mapping={"filename": output.name, "mime": "video/mp4", "size": "5"})

    with TestClient(dlp.app) as client:
        response = client.get(
            f"/v2/jobs/{job_id}/file",
            headers={
                "x-dlp-service-token": TOKEN,
                "x-job-owner": OWNER_A,
                "Range": range_header,
            },
        )

    assert response.status_code == expected_status
    assert response.content == expected_body
    if expected_status == 206:
        assert response.headers["accept-ranges"] == "bytes"
    assert response.headers["content-range"] == expected_content_range


def test_private_byte_range_still_requires_job_owner(fake_store, tmp_path):
    job_id = record(fake_store, status="READY")
    output = tmp_path / job_id / "media.mp4"
    output.parent.mkdir()
    output.write_bytes(b"media")
    fake_store.hset(dlp.job_key(job_id), mapping={"filename": output.name, "mime": "video/mp4", "size": "5"})

    with TestClient(dlp.app) as client:
        response = client.get(
            f"/v2/jobs/{job_id}/file",
            headers={
                "x-dlp-service-token": TOKEN,
                "x-job-owner": OWNER_B,
                "Range": "bytes=0-1",
            },
        )

    assert response.status_code == 404
