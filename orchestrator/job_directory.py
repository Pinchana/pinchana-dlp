"""Prepare host output directories for non-root DLP workers."""

import os
from pathlib import Path


def prepare_output_directory(output_dir: Path, worker_uid: int, worker_gid: int) -> None:
    output_dir.mkdir(parents=True, exist_ok=False)
    output_dir.chmod(0o700)
    os.chown(output_dir, worker_uid, worker_gid)
