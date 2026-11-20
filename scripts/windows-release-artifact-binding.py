"""Check candidate bytes against an inventory after its signature is verified.

This is a structural byte-binding check only. The caller must independently
authenticate the inventory, verify all executable signatures and the SBOM,
and qualify the exact snapshots before any publication is considered.
"""
import hashlib
import io
import json
import os
import re
import stat
import tarfile
import argparse
import zlib
from pathlib import Path

DIGEST = re.compile(r"[a-f0-9]{64}\Z")
COMMIT = re.compile(r"[a-f0-9]{40}\Z")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\Z")
COMPONENT = re.compile(r"[A-Za-z0-9._-]+\Z")
RESERVED = frozenset(("CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))))
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024
MAX_SBOM = 16 * 1024 * 1024
MAX_INVENTORY = 16 * 1024 * 1024
MAX_FILES = 20000


def _unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("Duplicate JSON key")
        out[key] = value
    return out


def _name(name, directory=False):
    if not isinstance(name, str):
        raise ValueError("Invalid archive name")
    name = name.removesuffix("/") if directory else name
    parts = name.split("/")
    if len(name) > 1024 or parts[0] != "package" or (len(parts) == 1 and not directory):
        raise ValueError("Invalid archive root")
    for part in parts:
        if (not part or len(part) > 255 or not COMPONENT.fullmatch(part) or part in (".", "..")
                or part.endswith(".") or part.split(".", 1)[0].upper() in RESERVED):
            raise ValueError("Invalid archive component")
    return name


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _artifact(value, expected_name, content):
    if (not isinstance(value, dict) or set(value) != {"name", "sha256"}
            or value["name"] != expected_name or not isinstance(value["sha256"], str)
            or not DIGEST.fullmatch(value["sha256"]) or value["sha256"] != _hash(content)):
        raise ValueError("Inventory artifact mismatch")


def _check_complete_stream(archive, tar_end):
    """Reject hidden data after tar EOF, trailing bytes and gzip members."""
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    total = 0
    tail_bytes = 0
    limit = MAX_EXPANDED + MAX_FILES * 4096 + 1024 * 1024
    try:
        for offset in range(0, len(archive), 65536):
            pending = archive[offset:offset + 65536]
            while pending:
                block = decoder.decompress(pending, 1024 * 1024)
                pending = decoder.unconsumed_tail
                if decoder.unused_data:
                    raise ValueError("Trailing or concatenated gzip data")
                start = max(0, tar_end - total)
                if start < len(block):
                    tail = block[start:]
                    tail_bytes += len(tail)
                    if any(tail):
                        raise ValueError("Data follows tar end")
                total += len(block)
                if total > limit or tail_bytes >= 1024 * 1024 + 1024:
                    raise ValueError("Expanded archive exceeds limit")
        if not decoder.eof or decoder.unused_data or tail_bytes < 1024:
            raise ValueError("Truncated gzip or tar end")
    except zlib.error as exc:
        raise ValueError("Invalid compressed stream") from exc


def validate_binding(archive, sbom, inventory, *, archive_name, sbom_name, version, architecture, source_commit):
    """Reject mismatched candidate snapshots; this does not validate a signature."""
    if (not isinstance(archive, bytes) or not 0 < len(archive) <= MAX_ARCHIVE
            or not isinstance(sbom, bytes) or not 0 < len(sbom) <= MAX_SBOM
            or not isinstance(inventory, bytes) or not 0 < len(inventory) <= MAX_INVENTORY
            or not isinstance(version, str) or not VERSION.fullmatch(version)
            or architecture not in ("amd64", "arm64") or not isinstance(source_commit, str) or not COMMIT.fullmatch(source_commit)
            or archive_name != f"tokentimer-agent-{version}-windows-{architecture}.tgz"
            or not isinstance(sbom_name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", sbom_name)):
        raise ValueError("Invalid candidate identity")
    try:
        data = json.loads(inventory, object_pairs_hook=_unique)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid inventory") from exc
    if (not isinstance(data, dict) or set(data) != {"schemaVersion", "sourceCommit", "version", "architecture", "archive", "sbom", "files"}
            or type(data["schemaVersion"]) is not int or data["schemaVersion"] != 1
            or data["sourceCommit"] != source_commit or data["version"] != version or data["architecture"] != architecture):
        raise ValueError("Inventory identity mismatch")
    _artifact(data["archive"], archive_name, archive)
    _artifact(data["sbom"], sbom_name, sbom)
    if not isinstance(data["files"], list) or not 0 < len(data["files"]) <= MAX_FILES:
        raise ValueError("Invalid inventory files")
    expected = {}
    for item in data["files"]:
        if (not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}
                or not isinstance(item["sha256"], str) or not DIGEST.fullmatch(item["sha256"])
                or type(item["size"]) is not int or not 0 <= item["size"] <= MAX_EXPANDED):
            raise ValueError("Invalid inventory file")
        name = _name(item["path"])
        key = name.lower()
        if key in expected:
            raise ValueError("Duplicate inventory path")
        expected[key] = (name, item["size"], item["sha256"])

    actual, seen, total = {}, {}, 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            for member in tar:
                if len(seen) >= MAX_FILES or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE):
                    raise ValueError("Unsupported archive member")
                name = _name(member.name, member.isdir())
                key = name.lower()
                if key in seen or member.size < 0 or (member.isdir() and member.size != 0):
                    raise ValueError("Duplicate or invalid archive member")
                seen[key] = member.isdir()
                if member.isdir():
                    continue
                total += member.size
                if total > MAX_EXPANDED:
                    raise ValueError("Archive expansion limit exceeded")
                stream = tar.extractfile(member)
                if stream is None:
                    raise ValueError("Archive content unavailable")
                digest = hashlib.sha256()
                count = 0
                while True:
                    part = stream.read(1024 * 1024)
                    if not part:
                        break
                    count += len(part)
                    digest.update(part)
                if count != member.size:
                    raise ValueError("Truncated archive member")
                actual[key] = (name, count, digest.hexdigest())
            tar_end = tar.offset
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise ValueError("Invalid archive") from exc
    for key in seen:
        segments = key.split("/")
        for index in range(1, len(segments)):
            parent = "/".join(segments[:index])
            if parent in seen and not seen[parent]:
                raise ValueError("Archive file is a parent directory")
    if actual != expected:
        raise ValueError("Inventory file content mismatch")
    _check_complete_stream(archive, tar_end)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "sbom", "inventory", "version", "architecture", "source-commit", "archive-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    archive = Path(args.archive)
    sbom = Path(args.sbom)
    def read(path, limit):
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("Candidate input must be a regular file")
            data = stream.read(limit + 1)
            if not data or len(data) > limit:
                raise ValueError("Candidate input size outside bounds")
            return data
    archive_data = read(archive, MAX_ARCHIVE)
    sbom_data = read(sbom, MAX_SBOM)
    inventory_data = read(args.inventory, MAX_INVENTORY)
    if not DIGEST.fullmatch(args.archive_sha256) or _hash(archive_data) != args.archive_sha256:
        raise ValueError("Independently bound archive digest mismatch")
    validate_binding(archive_data, sbom_data, inventory_data,
                     archive_name=archive.name, sbom_name=sbom.name, version=args.version,
                     architecture=args.architecture, source_commit=args.source_commit)
    # Output the hash of the same immutable bytes that were just checked, not
    # a second path read that could observe a replacement.
    print(_hash(inventory_data))


if __name__ == "__main__":
    main()
