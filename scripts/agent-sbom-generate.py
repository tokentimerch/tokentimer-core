"""Generate and validate an experimental Windows agent SBOM from staged bytes.

The caller must obtain the archive and tool hashes from independent trusted
sources. Run only on an isolated, unprivileged Linux build runner; same-UID
processes are trusted. This helper does not sign, publish, or prove transitive
completeness.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

SPEC = importlib.util.spec_from_file_location("agent_sbom_enrich", Path(__file__).with_name("agent-sbom-enrich.py"))
ENRICH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENRICH)
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
MAX_TOOL = 256 * 1024 * 1024


def trusted_temp_parent():
    if sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() == 0:
        raise ValueError("An isolated unprivileged Linux build runner is required")
    parent = Path("/tmp")
    entry = os.lstat(parent)
    if (not stat.S_ISDIR(entry.st_mode) or entry.st_uid not in (0, os.geteuid())
            or (entry.st_mode & 0o022 and not entry.st_mode & stat.S_ISVTX)):
        raise ValueError("Untrusted temporary directory parent")
    return str(parent)


def assert_private_workspace(path):
    entry = os.lstat(path)
    if not stat.S_ISDIR(entry.st_mode) or entry.st_uid != os.geteuid() or entry.st_mode & 0o077:
        raise ValueError("Temporary build workspace is not private")


def assert_trusted_output_parent(path):
    """Reject linked or untrusted writable ancestors on the isolated runner."""
    current = Path(path).absolute()
    while True:
        entry = os.lstat(current)
        if (not stat.S_ISDIR(entry.st_mode) or entry.st_uid not in (0, os.geteuid())
                or (entry.st_mode & 0o022 and not entry.st_mode & stat.S_ISVTX)):
            raise ValueError("Untrusted output directory")
        if current.parent == current:
            return
        current = current.parent


def read_bounded(path, limit):
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOINHERIT", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Input must be a regular file")
        data = stream.read(limit + 1)
    if not data or len(data) > limit:
        raise ValueError("Input size outside bounds")
    return data


def verify_tool(path, expected):
    if not SHA256.fullmatch(expected):
        raise ValueError("Invalid trusted tool digest")
    data = read_bounded(path, MAX_TOOL)
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("Trusted tool digest mismatch")
    return data


def generate(archive, archive_sha, node_zip, architecture, syft, syft_sha, validator, validator_sha):
    if not isinstance(archive, bytes) or not SHA256.fullmatch(archive_sha) or hashlib.sha256(archive).hexdigest() != archive_sha:
        raise ValueError("Candidate digest mismatch")
    syft_bytes = verify_tool(syft, syft_sha)
    validator_bytes = verify_tool(validator, validator_sha)
    # Before invoking the scanner, reject unsafe paths, unsupported entries,
    # gzip concatenation and expansion beyond the candidate's declared bounds.
    # This baseline is discarded: only the actual scanner output is returned.
    baseline = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                           "metadata": {"component": {"type": "file", "version": "sha256:" + archive_sha}},
                           "components": []}).encode()
    ENRICH.enrich(archive, archive_sha, node_zip, baseline, architecture)
    parent = trusted_temp_parent()
    with tempfile.TemporaryDirectory(prefix="agent-sbom-", dir=parent) as tmp:
        assert_private_workspace(tmp)
        root = Path(tmp)
        package = root / "candidate.tgz"
        scanner_output = root / "scanned.cdx.json"
        enriched_output = root / "enriched.cdx.json"
        scanner_tool = root / ("scanner.exe" if os.name == "nt" else "scanner")
        validator_tool = root / ("validator.exe" if os.name == "nt" else "validator")
        package.write_bytes(archive)
        scanner_tool.write_bytes(syft_bytes)
        validator_tool.write_bytes(validator_bytes)
        scanner_tool.chmod(0o500)
        validator_tool.chmod(0o500)
        # Do not inherit Syft, .NET or shell configuration from the caller.
        env = {key: os.environ[key] for key in ("SystemRoot", "WINDIR") if key in os.environ}
        env.update({"TMP": tmp, "TEMP": tmp})
        env.update({"SYFT_CHECK_FOR_APP_UPDATE": "false", "HOME": tmp, "DOTNET_CLI_HOME": tmp})
        def run(arguments):
            result = subprocess.run(arguments, cwd=tmp, env=env, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300, check=False)
            if result.returncode:
                raise ValueError("SBOM scanner or schema validation failed")
        run([str(scanner_tool), "scan", "file:" + str(package), "-o", "cyclonedx-json@1.6=" + str(scanner_output), "--quiet"])
        scanned = read_bounded(scanner_output, ENRICH.MAX_JSON)
        data = ENRICH.enrich(archive, archive_sha, node_zip, scanned, architecture)
        enriched_output.write_bytes(data)
        run([str(validator_tool), "validate", "--input-file", str(enriched_output), "--input-format", "json", "--input-version", "v1_6", "--fail-on-errors"])
        # Verify the validator did not alter the exact output bytes.
        if read_bounded(enriched_output, ENRICH.MAX_JSON) != data:
            raise ValueError("Validated SBOM changed")
        return data


def write_new_output(path, data):
    """Atomically link a complete, synced owner-only file without replacement."""
    target = Path(path).absolute()
    assert_trusted_output_parent(target.parent)
    fd, temporary = tempfile.mkstemp(prefix=".agent-sbom-output-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        # link is atomic and fails if any target already exists, unlike rename
        # on POSIX, which can replace an existing file.
        os.link(temporary, target, follow_symlinks=False)
        directory = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "archive-sha256", "node-zip", "architecture", "syft", "syft-sha256", "validator", "validator-sha256", "out"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    data = generate(read_bounded(args.archive, ENRICH.MAX_ARCHIVE), args.archive_sha256,
                    read_bounded(args.node_zip, ENRICH.MAX_ARCHIVE), args.architecture,
                    args.syft, args.syft_sha256, args.validator, args.validator_sha256)
    write_new_output(args.out, data)


if __name__ == "__main__":
    main()
