import os
from pathlib import Path

from orchestrator.job_directory import prepare_output_directory


def test_output_directory_is_restricted_before_ownership_transfer(monkeypatch):
    events = []
    output_dir = Path("/jobs/example")

    monkeypatch.setattr(Path, "mkdir", lambda self, **kwargs: events.append(("mkdir", self, kwargs)))
    monkeypatch.setattr(Path, "chmod", lambda self, mode: events.append(("chmod", self, mode)))
    monkeypatch.setattr(os, "chown", lambda path, uid, gid: events.append(("chown", path, uid, gid)))

    prepare_output_directory(output_dir, 10001, 10001)

    assert events == [
        ("mkdir", output_dir, {"parents": True, "exist_ok": False}),
        ("chmod", output_dir, 0o700),
        ("chown", output_dir, 10001, 10001),
    ]
