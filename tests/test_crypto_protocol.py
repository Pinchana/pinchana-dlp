import base64
import json
import subprocess
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import x25519

from worker.main import decrypt_cookies, sanitize_error, validate_netscape_cookies


COOKIE_MARKER = "COOKIE_MARKER_NEVER_PERSIST\tsecret-value"
NETSCAPE = f"# Netscape HTTP Cookie File\n.youtube.com\tTRUE\t/\tTRUE\t0\t{COOKIE_MARKER}\n"


def browser_envelope(worker_private, job_id="12345678-1234-4234-9234-123456789abc", key_id="wk-test-vector"):
    worker_public = base64.b64encode(worker_private.public_key().public_bytes_raw()).decode()
    script = Path(__file__).with_name("browser_vector.mjs")
    result = subprocess.run(
        ["node", str(script), json.dumps({"workerPubKey": worker_public, "jobId": job_id, "keyId": key_id, "plaintext": NETSCAPE})],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout), job_id, key_id


def test_browser_webcrypto_vector_decrypts_in_python_worker():
    private = x25519.X25519PrivateKey.generate()
    envelope, job_id, key_id = browser_envelope(private)
    assert bytes(decrypt_cookies(envelope, private, job_id, key_id)) == NETSCAPE.encode()


def test_tampered_ciphertext_is_rejected():
    private = x25519.X25519PrivateKey.generate()
    envelope, job_id, key_id = browser_envelope(private)
    ciphertext = bytearray(base64.b64decode(envelope["ciphertext"]))
    ciphertext[-1] ^= 1
    envelope["ciphertext"] = base64.b64encode(ciphertext).decode()
    with pytest.raises(InvalidTag):
        decrypt_cookies(envelope, private, job_id, key_id)


def test_wrong_worker_key_and_wrong_authenticated_job_are_rejected():
    private = x25519.X25519PrivateKey.generate()
    envelope, job_id, key_id = browser_envelope(private)
    with pytest.raises(InvalidTag):
        decrypt_cookies(envelope, x25519.X25519PrivateKey.generate(), job_id, key_id)
    with pytest.raises(InvalidTag):
        decrypt_cookies(envelope, private, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", key_id)


def test_cookie_values_are_not_exposed_by_log_sanitizer():
    assert "secret-value" not in sanitize_error("Cookie: secret-value https://youtube.com/watch?v=abc")


def test_netscape_validation_accepts_httponly_cookie_lines():
    validate_netscape_cookies(
        b"# Netscape HTTP Cookie File\n#HttpOnly_.youtube.com\tTRUE\t/\tTRUE\t0\tSID\tsecret\n"
    )
