import base64
import time

import fakeredis
import pytest
from fastapi import HTTPException
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
    dlp.submit_job(job_id, dlp.SubmitRequest(url="https://example.com/video", cookiesEnc=envelope), context())
    persisted = fake_store.get(f"{dlp.job_key(job_id)}:payload")
    assert "COOKIE_MARKER_NEVER_PERSIST" not in persisted
    assert envelope.ciphertext in persisted


def test_expired_worker_key_rejects_submission(fake_store, monkeypatch):
    job_id = record(fake_store)
    fake_store.hset(dlp.job_key(job_id), "keyExpiresAt", int(time.time()) - 1)
    monkeypatch.setattr(dlp, "validate_public_url", lambda value: value)
    with pytest.raises(HTTPException) as failure:
        dlp.submit_job(job_id, dlp.SubmitRequest(url="https://example.com/video"), context())
    assert failure.value.status_code == 410


@pytest.mark.parametrize("url", ["http://127.0.0.1/file", "http://[::1]/file", "http://localhost/file", "http://169.254.169.254/latest/meta-data"])
def test_ssrf_targets_are_rejected(url):
    with pytest.raises(HTTPException) as failure:
        dlp.validate_public_url(url)
    assert failure.value.status_code == 400


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
