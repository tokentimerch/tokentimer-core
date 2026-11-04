"""Immutable, bounded byte snapshots for a future Windows release promotion.

This helper checks only byte digests. It does not authenticate the candidate,
verify a signature, collect qualification, or publish a release. Callers must
obtain expected digests independently and must never reopen paths for upload.
"""
from hashlib import sha256
import os
import stat
from pathlib import Path
import re
from types import MappingProxyType

NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z")
DIGEST = re.compile(r"[a-f0-9]{64}\Z")
MAX_FILE = 128 * 1024 * 1024
MAX_TOTAL = 384 * 1024 * 1024
MAX_ASSETS = 24


def snapshot_assets(directory, expected):
    """Read once, check each digest and retain those exact immutable bytes."""
    if not isinstance(expected, dict) or not 1 <= len(expected) <= MAX_ASSETS:
        raise ValueError("Invalid candidate asset set")
    root = Path(directory)
    snapshots = {}
    total = 0
    for name, digest in expected.items():
        if not isinstance(name, str) or not NAME.fullmatch(name) or not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise ValueError("Invalid candidate asset identity")
        path = root / name
        # Bounded reads ensure the immutable snapshot, not a later reopened
        # filesystem path, is what a future uploader must send.
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOINHERIT", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise ValueError("Candidate asset must be a regular file")
            content = source.read(min(MAX_FILE, MAX_TOTAL - total) + 1)
        total += len(content)
        if len(content) > MAX_FILE or total > MAX_TOTAL:
            raise ValueError("Candidate asset size exceeds bound")
        if sha256(content).hexdigest() != digest:
            raise ValueError("Candidate asset digest mismatch")
        snapshots[name] = content
    return MappingProxyType(snapshots)
