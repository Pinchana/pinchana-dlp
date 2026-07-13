"""Internal Pinchana DLP protocol-v2 API.

Only pinchana-server may call the gateway routes. Workers authenticate with a
unique credential that is generated for, and expires with, one job.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import secrets
import socket
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

import redis
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

logger = logging.getLogger("pinchana_dlp")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

PROTOCOL_VERSION = 2
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
JOBS_DIR = Path(os.getenv("JOBS_DIR", "/data/jobs"))
GATEWAY_SERVICE_TOKEN = os.getenv("DLP_GATEWAY_TOKEN", "")
JOB_TTL_SECONDS = int(os.getenv("JOB_TTL_SECONDS", "3600"))
KEY_TTL_SECONDS = min(int(os.getenv("KEY_TTL_SECONDS", "300")), 600)
ALLOCATION_WAIT_SECONDS = float(os.getenv("ALLOCATION_WAIT_SECONDS", "12"))
MAX_ACTIVE_JOBS = int(os.getenv("MAX_ACTIVE_JOBS", "10"))
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "10"))
MAX_REQUEST_BYTES = int(os.getenv("MAX_REQUEST_BYTES", str(320 * 1024)))
MAX_CIPHERTEXT_BYTES = int(os.getenv("MAX_CIPHERTEXT_BYTES", str(256 * 1024)))
MAX_OUTPUT_BYTES = int(os.getenv("MAX_OUTPUT_BYTES", str(2 * 1024 * 1024 * 1024)))

r = redis.Redis.from_url(REDIS_URL, decode_responses=True)


def now() -> int:
    return int(time.time())


def job_key(job_id: str) -> str:
    return f"dlp:job:{job_id}"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _decode_b64(value: str, *, exact: int | None = None, maximum: int | None = None) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ValueError("invalid base64") from exc
    if exact is not None and len(decoded) != exact:
        raise ValueError(f"must decode to {exact} bytes")
    if maximum is not None and len(decoded) > maximum:
        raise ValueError("decoded value is too large")
    return decoded


class CookiesEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[2]
    keyId: str = Field(min_length=8, max_length=128)
    clientPubKey: str = Field(min_length=40, max_length=64)
    salt: str = Field(min_length=20, max_length=64)
    iv: str = Field(min_length=12, max_length=32)
    ciphertext: str = Field(min_length=20, max_length=480_000)

    @field_validator("clientPubKey")
    @classmethod
    def valid_public_key(cls, value: str) -> str:
        _decode_b64(value, exact=32)
        return value

    @field_validator("salt")
    @classmethod
    def valid_salt(cls, value: str) -> str:
        _decode_b64(value, exact=32)
        return value

    @field_validator("iv")
    @classmethod
    def valid_iv(cls, value: str) -> str:
        _decode_b64(value, exact=12)
        return value

    @field_validator("ciphertext")
    @classmethod
    def valid_ciphertext(cls, value: str) -> str:
        _decode_b64(value, maximum=MAX_CIPHERTEXT_BYTES)
        return value


class SubmitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=10, max_length=2048)
    quality: Literal["best", "1080p", "720p", "480p", "360p", "audio"] = "best"
    cookiesEnc: CookiesEnvelope | None = None


class WorkerRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    keyId: str = Field(min_length=8, max_length=128)
    workerPubKey: str = Field(min_length=40, max_length=64)
    expiresAt: int

    @field_validator("workerPubKey")
    @classmethod
    def valid_public_key(cls, value: str) -> str:
        _decode_b64(value, exact=32)
        return value


class ProgressRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stage: Literal["starting", "decrypting", "downloading", "merging", "finalizing"]
    progress: float = Field(ge=0, le=100)


class CompleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filename: str = Field(min_length=1, max_length=255)
    size: int = Field(gt=0, le=MAX_OUTPUT_BYTES)
    mime: str = Field(min_length=3, max_length=128)


class FailRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    error: str = Field(min_length=1, max_length=500)
    stage: str | None = Field(default=None, max_length=64)


class GatewayContext(BaseModel):
    owner: str


def require_gateway(
    x_dlp_service_token: Annotated[str | None, Header()] = None,
    x_job_owner: Annotated[str | None, Header()] = None,
) -> GatewayContext:
    if not GATEWAY_SERVICE_TOKEN or not x_dlp_service_token or not hmac.compare_digest(
        x_dlp_service_token, GATEWAY_SERVICE_TOKEN
    ):
        raise HTTPException(403, "Invalid gateway credential")
    if not x_job_owner or len(x_job_owner) > 256:
        raise HTTPException(403, "Missing job owner")
    return GatewayContext(owner=_digest(x_job_owner))


def require_worker(job_id: str, x_job_token: Annotated[str | None, Header()] = None) -> dict[str, str]:
    record = r.hgetall(job_key(job_id))
    if not record or not x_job_token or not hmac.compare_digest(
        record.get("credentialDigest", ""), _digest(x_job_token)
    ):
        raise HTTPException(403, "Invalid job credential")
    if int(record.get("expiresAt", "0")) <= now():
        raise HTTPException(410, "Job expired")
    return record


def owned_job(job_id: str, context: GatewayContext) -> dict[str, str]:
    record = r.hgetall(job_key(job_id))
    if not record:
        raise HTTPException(404, "Unknown or expired job")
    if not hmac.compare_digest(record.get("ownerDigest", ""), context.owner):
        raise HTTPException(404, "Unknown or expired job")
    if int(record.get("expiresAt", "0")) <= now():
        raise HTTPException(410, "Job expired")
    return record


def validate_public_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(400, "A public HTTP(S) URL is required")
    if parsed.username or parsed.password or parsed.port not in {None, 80, 443}:
        raise HTTPException(400, "URL credentials and custom ports are not allowed")
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(".local"):
        raise HTTPException(400, "Private network targets are not allowed")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(hostname, parsed.port or 443)}
    except socket.gaierror as exc:
        raise HTTPException(400, "URL hostname could not be resolved") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        if not ip.is_global:
            raise HTTPException(400, "Private network targets are not allowed")
    return value


def check_rate_limit(owner: str) -> None:
    bucket = f"dlp:rate:{owner}:{now() // 60}"
    count = r.incr(bucket)
    if count == 1:
        r.expire(bucket, 120)
    if count > RATE_LIMIT_PER_MINUTE:
        raise HTTPException(429, "DLP rate limit exceeded")


def transition(job_id: str, allowed: set[str], target: str, updates: dict[str, Any] | None = None) -> dict[str, str]:
    key = job_key(job_id)
    with r.pipeline() as pipe:
        while True:
            try:
                pipe.watch(key)
                record = pipe.hgetall(key)
                if not record:
                    raise HTTPException(404, "Unknown or expired job")
                if record.get("status") not in allowed:
                    raise HTTPException(409, f"Job cannot transition from {record.get('status')}")
                mapping = {"status": target, "updatedAt": str(now())}
                if updates:
                    mapping.update({key: str(value) for key, value in updates.items()})
                pipe.multi()
                pipe.hset(key, mapping=mapping)
                pipe.execute()
                return {**record, **mapping}
            except redis.WatchError:
                continue


def public_status(record: dict[str, str]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "jobId": record["jobId"],
        "status": record["status"],
        "expiresAt": int(record["expiresAt"]),
    }
    for field in ("stage", "progress", "error", "size", "mime"):
        if field in record:
            result[field] = float(record[field]) if field == "progress" else int(record[field]) if field == "size" else record[field]
    return result


@asynccontextmanager
async def lifespan(_app: FastAPI):
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    r.ping()
    yield


app = FastAPI(title="Pinchana DLP", version="2.0.0", lifespan=lifespan)


@app.middleware("http")
async def request_size_limit(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_REQUEST_BYTES:
        return __import__("fastapi").responses.JSONResponse({"detail": "Request too large"}, status_code=413)
    return await call_next(request)


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "protocol": PROTOCOL_VERSION, "redis": bool(r.ping())}


@app.post("/v2/jobs")
def allocate_job(context: GatewayContext = Depends(require_gateway)):
    check_rate_limit(context.owner)
    r.zremrangebyscore("dlp:active", "-inf", now())
    if r.zcard("dlp:active") >= MAX_ACTIVE_JOBS:
        raise HTTPException(503, "DLP capacity is full")

    job_id = str(uuid.uuid4())
    credential = secrets.token_urlsafe(32)
    created_at = now()
    expires_at = created_at + JOB_TTL_SECONDS
    record = {
        "jobId": job_id,
        "ownerDigest": context.owner,
        "credentialDigest": _digest(credential),
        "status": "ALLOCATING",
        "createdAt": str(created_at),
        "updatedAt": str(created_at),
        "expiresAt": str(expires_at),
    }
    r.hset(job_key(job_id), mapping=record)
    r.expireat(job_key(job_id), expires_at)
    r.zadd("dlp:active", {job_id: expires_at})
    r.rpush("dlp:orchestrator:spawn", json.dumps({"jobId": job_id, "credential": credential}))

    deadline = time.monotonic() + ALLOCATION_WAIT_SECONDS
    while time.monotonic() < deadline:
        current = r.hgetall(job_key(job_id))
        if current.get("status") == "ALLOCATED":
            return {
                "jobId": job_id,
                "keyId": current["keyId"],
                "workerPubKey": current["workerPubKey"],
                "expiresAt": int(current["keyExpiresAt"]),
            }
        if current.get("status") == "FAILED":
            raise HTTPException(503, current.get("error", "Worker allocation failed"))
        time.sleep(0.05)
    transition(job_id, {"ALLOCATING"}, "FAILED", {"error": "Worker allocation timed out"})
    raise HTTPException(504, "Worker allocation timed out")


@app.post("/v2/jobs/{job_id}/submit")
def submit_job(job_id: str, request: SubmitRequest, context: GatewayContext = Depends(require_gateway)):
    record = owned_job(job_id, context)
    if record.get("status") != "ALLOCATED":
        raise HTTPException(409, "Job has already been submitted")
    if int(record["keyExpiresAt"]) <= now():
        transition(job_id, {"ALLOCATED"}, "EXPIRED", {"error": "Worker key expired"})
        raise HTTPException(410, "Worker key expired")
    if request.cookiesEnc and request.cookiesEnc.keyId != record["keyId"]:
        raise HTTPException(400, "Cookie envelope key does not match the allocated worker")
    url = validate_public_url(request.url)
    payload = request.model_dump(mode="json")
    payload["url"] = url
    transition(job_id, {"ALLOCATED"}, "QUEUED")
    r.set(f"{job_key(job_id)}:payload", json.dumps(payload), exat=int(record["expiresAt"]))
    return {"jobId": job_id, "status": "QUEUED"}


@app.get("/v2/jobs/{job_id}")
def get_job(job_id: str, context: GatewayContext = Depends(require_gateway)):
    return public_status(owned_job(job_id, context))


@app.get("/v2/jobs/{job_id}/file")
def get_file(job_id: str, context: GatewayContext = Depends(require_gateway)):
    record = owned_job(job_id, context)
    if record.get("status") != "READY":
        raise HTTPException(409, "File is not ready")
    filename = Path(record.get("filename", "")).name
    path = (JOBS_DIR / job_id / filename).resolve()
    expected_parent = (JOBS_DIR / job_id).resolve()
    if not filename or path.parent != expected_parent or not path.is_file():
        raise HTTPException(404, "File is unavailable")
    return FileResponse(path, filename=filename, media_type=record.get("mime", "application/octet-stream"))


@app.post("/internal/jobs/{job_id}/register")
def register_worker(job_id: str, request: WorkerRegisterRequest, record: dict[str, str] = Depends(require_worker)):
    key_expires_at = min(request.expiresAt, now() + KEY_TTL_SECONDS, int(record["expiresAt"]))
    if key_expires_at <= now():
        raise HTTPException(400, "Worker key is already expired")
    transition(job_id, {"ALLOCATING"}, "ALLOCATED", {
        "keyId": request.keyId,
        "workerPubKey": request.workerPubKey,
        "keyExpiresAt": key_expires_at,
    })
    return {"ok": True}


@app.get("/internal/jobs/{job_id}/payload")
def worker_payload(job_id: str, _record: dict[str, str] = Depends(require_worker)):
    payload_key = f"{job_key(job_id)}:payload"
    payload = r.getdel(payload_key)
    if not payload:
        raise HTTPException(404, "Payload not available")
    try:
        transition(job_id, {"QUEUED"}, "RUNNING", {"stage": "starting", "progress": 0})
    except HTTPException:
        r.delete(payload_key)
        raise
    return json.loads(payload)


@app.post("/internal/jobs/{job_id}/progress")
def worker_progress(job_id: str, request: ProgressRequest, _record: dict[str, str] = Depends(require_worker)):
    transition(job_id, {"RUNNING"}, "RUNNING", request.model_dump())
    return {"ok": True}


@app.post("/internal/jobs/{job_id}/complete")
def worker_complete(job_id: str, request: CompleteRequest, _record: dict[str, str] = Depends(require_worker)):
    filename = Path(request.filename).name
    if filename != request.filename:
        raise HTTPException(400, "Invalid filename")
    path = JOBS_DIR / job_id / filename
    if not path.is_file() or path.stat().st_size != request.size:
        raise HTTPException(400, "Output file does not match completion report")
    transition(job_id, {"RUNNING"}, "READY", request.model_dump())
    r.zrem("dlp:active", job_id)
    return {"ok": True}


@app.post("/internal/jobs/{job_id}/fail")
def worker_fail(job_id: str, request: FailRequest, _record: dict[str, str] = Depends(require_worker)):
    transition(job_id, {"ALLOCATING", "ALLOCATED", "QUEUED", "RUNNING"}, "FAILED", request.model_dump(exclude_none=True))
    r.zrem("dlp:active", job_id)
    return {"ok": True}
