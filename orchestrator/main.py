"""Docker-socket holder for spawning hardened one-job DLP workers."""

import hashlib
import json
import logging
import os
import shutil
import threading
import time
from pathlib import Path

import docker
import redis

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("pinchana_dlp_orchestrator")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
WORKER_IMAGE = os.getenv("WORKER_IMAGE", "pinchana-dlp-worker:latest")
WORKER_NETWORK = os.getenv("WORKER_NETWORK", "pinchana-dlp-worker")
API_URL = os.getenv("DLP_API_URL", "http://dlp-api:8080")
HOST_JOBS_DIR = Path(os.getenv("HOST_JOBS_DIR", "/data/jobs")).resolve()
OUTPUT_LIMIT = int(os.getenv("MAX_OUTPUT_BYTES", str(2 * 1024 * 1024 * 1024)))
EXECUTION_TIMEOUT = int(os.getenv("EXECUTION_TIMEOUT_SECONDS", "900"))
MEMORY_LIMIT = os.getenv("WORKER_MEMORY_LIMIT", "768m")
PIDS_LIMIT = int(os.getenv("WORKER_PIDS_LIMIT", "128"))
VPN_PROXY_URL = os.getenv("VPN_PROXY_URL", "")
HEALTH_FILE = Path(os.getenv("HEALTH_FILE", "/tmp/orchestrator-ready"))
WORKER_UID = int(os.getenv("WORKER_UID", "10001"))
WORKER_GID = int(os.getenv("WORKER_GID", "10001"))

r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
docker_client = docker.from_env()


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def fail(job_id: str, message: str) -> None:
    key = f"dlp:job:{job_id}"
    r.hset(key, mapping={"status": "FAILED", "error": message[:500], "updatedAt": int(time.time())})
    r.zrem("dlp:active", job_id)


def monitor(container, job_id: str, output_dir: Path) -> None:
    deadline = time.monotonic() + EXECUTION_TIMEOUT + 120
    while time.monotonic() < deadline:
        try:
            container.reload()
            if container.status not in {"created", "running", "restarting"}:
                break
        except docker.errors.NotFound:
            break
        time.sleep(2)
    else:
        try:
            container.kill()
        except docker.errors.NotFound:
            pass
        fail(job_id, "Worker exceeded its forced lifetime")
    status = r.hget(f"dlp:job:{job_id}", "status")
    if status not in {"READY", "FAILED", "EXPIRED"}:
        fail(job_id, "Worker exited before completing the job")
        status = "FAILED"
    if status != "READY":
        shutil.rmtree(output_dir, ignore_errors=True)


def spawn(message: dict[str, str]) -> None:
    job_id = message.get("jobId", "")
    credential = message.get("credential", "")
    record = r.hgetall(f"dlp:job:{job_id}")
    if not record or record.get("status") != "ALLOCATING" or record.get("credentialDigest") != digest(credential):
        return

    output_dir = HOST_JOBS_DIR / job_id
    environment = {
        "JOB_ID": job_id,
        "JOB_TOKEN": credential,
        "DLP_API_URL": API_URL,
        "OUTPUT_DIR": "/output",
        "EXECUTION_TIMEOUT_SECONDS": str(EXECUTION_TIMEOUT),
        "MAX_OUTPUT_BYTES": str(OUTPUT_LIMIT),
    }
    if VPN_PROXY_URL:
        environment["VPN_PROXY_URL"] = VPN_PROXY_URL
    try:
        output_dir.mkdir(parents=True, exist_ok=False)
        os.chown(output_dir, WORKER_UID, WORKER_GID)
        output_dir.chmod(0o700)
        container = docker_client.containers.run(
            WORKER_IMAGE,
            detach=True,
            name=f"pinchana-dlp-{job_id}",
            environment=environment,
            volumes={str(output_dir): {"bind": "/output", "mode": "rw"}},
            tmpfs={"/run/cookies": "rw,noexec,nosuid,nodev,size=1m,uid=10001,gid=10001,mode=0700", "/tmp": "rw,noexec,nosuid,nodev,size=64m,uid=10001,gid=10001"},
            network=WORKER_NETWORK,
            read_only=True,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            mem_limit=MEMORY_LIMIT,
            nano_cpus=1_000_000_000,
            pids_limit=PIDS_LIMIT,
            auto_remove=True,
            labels={"pinchana.dlp.job": job_id},
        )
        r.hset(f"dlp:job:{job_id}", mapping={"containerId": container.id})
        threading.Thread(target=monitor, args=(container, job_id, output_dir), daemon=True).start()
    except Exception:
        logger.exception("worker_spawn_failed job=%s", job_id)
        shutil.rmtree(output_dir, ignore_errors=True)
        fail(job_id, "Worker could not be started")


def main() -> None:
    HOST_JOBS_DIR.mkdir(parents=True, exist_ok=True)
    r.ping()
    docker_client.ping()
    try:
        docker_client.images.get(WORKER_IMAGE)
    except docker.errors.ImageNotFound:
        logger.info("pulling_worker_image image=%s", WORKER_IMAGE)
        docker_client.images.pull(WORKER_IMAGE)
    logger.info("orchestrator_ready")
    HEALTH_FILE.touch(mode=0o600)
    last_cleanup = 0.0
    while True:
        HEALTH_FILE.touch(mode=0o600)
        item = r.blpop("dlp:orchestrator:spawn", timeout=5)
        if time.monotonic() - last_cleanup > 60:
            for path in HOST_JOBS_DIR.iterdir():
                if path.is_dir() and not r.exists(f"dlp:job:{path.name}"):
                    shutil.rmtree(path, ignore_errors=True)
            last_cleanup = time.monotonic()
        if not item:
            continue
        try:
            spawn(json.loads(item[1]))
        except Exception:
            logger.exception("invalid_spawn_message")


if __name__ == "__main__":
    main()
