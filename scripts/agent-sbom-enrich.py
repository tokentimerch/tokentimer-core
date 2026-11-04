"""Bind executable coverage and the Node license to a scanned Windows archive.

This experimental enrichment does not establish a complete SBOM or authorize a
release. Its caller must authenticate the candidate, trust the scanner and
validate the complete CycloneDX schema and transitive dependency inventory.
"""
import argparse
import base64
from collections import Counter
import hashlib
import io
import json
from pathlib import PurePosixPath
import re
import tarfile
import zipfile

MAX_ARCHIVE = 128 * 1024 * 1024
MAX_EXPANDED = 512 * 1024 * 1024
MAX_ENTRIES = 10000
MAX_JSON = 16 * 1024 * 1024
POLICY = {
    "amd64": ("x64", "0ae68406b42d7725661da979b1403ec9926da205c6770827f33aac9d8f26e821", "9a4eb5f1c29c6a2e93852ead46b999e284a6a5ca8bab4d4e241d587d025a52de"),
    "arm64": ("arm64", "f274669adb93b1fd0fbf8f21fd078609e9dcc84333d4f2718d2dde3f9a161a01", "c7225670c3f477778e18c43a55867f7a0d76468221245e5981ab80eb953c8102"),
}
NODE_VERSION = "24.18.0"
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
SEGMENT = re.compile(r"[A-Za-z0-9._-]+\Z")
RESERVED = frozenset(("CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique_json(data):
    def pairs(values):
        out = {}
        for key, value in values:
            if key in out:
                raise ValueError("Duplicate JSON key")
            out[key] = value
        return out
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_JSON:
        raise ValueError("Invalid SBOM size")
    try:
        def invalid_constant(_value):
            raise ValueError("Invalid JSON numeric constant")
        return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("Invalid SBOM JSON") from None


def enrich(archive, expected_archive_sha, upstream, sbom, architecture, policy=POLICY, version=NODE_VERSION):
    """Return enriched CycloneDX bytes; inputs must be read as immutable snapshots."""
    if (architecture not in policy or not isinstance(expected_archive_sha, str) or not SHA256.fullmatch(expected_archive_sha)
            or not isinstance(archive, bytes) or not 0 < len(archive) <= MAX_ARCHIVE or sha(archive) != expected_archive_sha
            or not isinstance(upstream, bytes) or not 0 < len(upstream) <= MAX_ARCHIVE):
        raise ValueError("Invalid candidate archive")
    upstream_arch, upstream_sha, runtime_sha = policy[architecture]
    if sha(upstream) != upstream_sha:
        raise ValueError("Untrusted upstream Node archive")
    source_prefix = f"node-v{version}-win-{upstream_arch}/"
    try:
        with zipfile.ZipFile(io.BytesIO(upstream)) as nodezip:
            names = nodezip.namelist()
            counts = Counter(names)
            if len(names) > MAX_ENTRIES or any(counts[source_prefix + name] != 1 for name in ("LICENSE", "node.exe")):
                raise ValueError("Invalid upstream runtime entries")
            license_entry = nodezip.getinfo(source_prefix + "LICENSE")
            node_entry = nodezip.getinfo(source_prefix + "node.exe")
            if not 0 < license_entry.file_size <= 2 * 1024 * 1024 or not 0 < node_entry.file_size <= MAX_ARCHIVE:
                raise ValueError("Invalid upstream runtime entry size")
            license_bytes = nodezip.read(license_entry)
            upstream_node = nodezip.read(node_entry)
    except (zipfile.BadZipFile, RuntimeError):
        raise ValueError("Invalid upstream runtime archive") from None
    if sha(upstream_node) != runtime_sha:
        raise ValueError("Upstream runtime digest differs")
    bom = unique_json(sbom)
    if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.6" or type(bom.get("version")) is not int or bom["version"] < 1 or not isinstance(bom.get("components"), list):
        raise ValueError("Expected CycloneDX 1.6 SBOM")
    metadata = bom.get("metadata", {})
    component = metadata.get("component", {}) if isinstance(metadata, dict) else {}
    if not isinstance(component, dict) or component.get("type") != "file" or component.get("version") != "sha256:" + expected_archive_sha:
        raise ValueError("Scanner SBOM source does not match archive")
    binaries, license_found, runtime_found, seen = {}, False, False, {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            for index, entry in enumerate(tar):
                name = entry.name
                parts = PurePosixPath(name).parts
                segments = name.rstrip("/").split("/") if entry.isdir() else name.split("/")
                if (index >= MAX_ENTRIES or len(name) > 1024 or not parts or parts[0] != "package" or "\\" in name
                        or name.startswith("/") or name.lower().rstrip("/") in seen
                        or (len(parts) == 1 and not entry.isdir())
                        or any(not part or len(part) > 255 or not SEGMENT.fullmatch(part) or part in (".", "..")
                               or part.endswith(".") or part.split(".", 1)[0].upper() in RESERVED for part in segments)):
                    raise ValueError("Unsafe or duplicate archive path")
                seen[name.lower().rstrip("/")] = entry.isdir()
                if not (entry.isfile() or entry.isdir()) or entry.size < 0 or (entry.isdir() and entry.size != 0):
                    raise ValueError("Unsupported archive entry")
                total += entry.size
                if total > MAX_EXPANDED:
                    raise ValueError("Archive expansion exceeds limit")
                if not entry.isfile():
                    continue
                if name.lower().endswith(".exe") or name == "package/runtime/LICENSE":
                    if entry.size <= 0 or entry.size > MAX_ARCHIVE:
                        raise ValueError("Invalid covered entry size")
                    source = tar.extractfile(entry)
                    if source is None:
                        raise ValueError("Unreadable archive entry")
                    data = source.read(MAX_ARCHIVE + 1)
                    if len(data) != entry.size:
                        raise ValueError("Truncated archive entry")
                    if name == "package/runtime/LICENSE":
                        license_found = data == license_bytes
                    else:
                        binaries[name] = sha(data)
                        if name == f"package/runtime/{architecture}/node.exe":
                            runtime_found = binaries[name] == runtime_sha
    except (tarfile.TarError, OSError, EOFError):
        raise ValueError("Invalid candidate archive") from None
    if not license_found or not runtime_found or not binaries:
        raise ValueError("Runtime or license differs from authenticated upstream")
    for name in seen:
        parts = name.split("/")
        for index in range(1, len(parts)):
            parent = "/".join(parts[:index])
            if parent in seen and not seen[parent]:
                raise ValueError("Archive file is also a parent directory")
    refs = set()
    for item in bom["components"]:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not item["name"].strip():
            raise ValueError("Invalid scanner component")
        ref = item.get("bom-ref")
        if ref is not None:
            if not isinstance(ref, str) or not ref or ref in refs:
                raise ValueError("Duplicate or invalid SBOM reference")
            refs.add(ref)
    for name, digest in sorted(binaries.items()):
        ref = "urn:tokentimer:archive-file:sha256:" + digest + ":" + sha(name.encode())
        if ref in refs:
            raise ValueError("SBOM reference collision")
        item = {"type": "file", "name": name.rsplit("/", 1)[-1], "bom-ref": ref,
                "hashes": [{"alg": "SHA-256", "content": digest}],
                "properties": [{"name": "tokentimer:archive:path", "value": name}]}
        if name == f"package/runtime/{architecture}/node.exe":
            item["version"] = version
            # The pinned upstream notice contains licenses for Node and its
            # bundled components; retain the whole notice rather than assert
            # that the complete binary is covered by one SPDX identifier.
            item["licenses"] = [{"license": {"name": "Node.js bundled license notices", "text": {
                "contentType": "text/plain", "encoding": "base64", "content": base64.b64encode(license_bytes).decode("ascii")}}}]
            item["properties"].append({"name": "tokentimer:runtime:license-sha256", "value": sha(license_bytes)})
        bom["components"].append(item)
    output = (json.dumps(bom, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(output) > MAX_JSON:
        raise ValueError("Enriched SBOM size exceeds limit")
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--node-zip", required=True)
    parser.add_argument("--sbom", required=True)
    parser.add_argument("--architecture", choices=tuple(POLICY), required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    def read(path, limit):
        with open(path, "rb") as f:
            data = f.read(limit + 1)
        if len(data) > limit:
            raise ValueError("Input size exceeds limit")
        return data
    data = enrich(read(args.archive, MAX_ARCHIVE), args.archive_sha256, read(args.node_zip, MAX_ARCHIVE), read(args.sbom, MAX_JSON), args.architecture)
    with open(args.out, "xb") as out:
        out.write(data)


if __name__ == "__main__":
    main()
