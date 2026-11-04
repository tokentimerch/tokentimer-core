"""Bind a future Windows qualification matrix to the same staged artifacts.

Inputs must come from the trusted GitHub API and already verified artifact ZIPs;
this module does not authenticate reports, validate signatures/SBOMs, retrieve
edition manifests or authorize publication. Existing workflows do not produce
these final-package reports, so this is intentionally not a release gate.
"""
import base64
import binascii
import json
import hashlib
import io
import re
import zipfile

DIGEST = re.compile(r"[a-f0-9]{64}\Z")
COMMIT = re.compile(r"[a-f0-9]{40}\Z")
ROLES = frozenset(("archive", "checksum", "signature", "sbom", "inventory", "launcher"))
EDITION_REPOS = {
    "core": ("tokentimerch/tokentimer-core", "main", ".github/workflows/certops-windows-e2e.yml"),
    "cloud": ("tokentimerch/tokentimer-cloud", "main", ".github/workflows/certops-overlay-qualification.yml"),
    "enterprise": ("tokentimerch/tokentimer-enterprise", "master", ".github/workflows/certops-qualification.yml"),
}
NATIVE_SYSTEMS = frozenset(("windows-server-2016", "windows-server-2019", "windows-server-2022", "windows-server-2025"))


def edition_pin_from_manifest(raw, edition):
    """Extract the composition pin from independently fetched manifest bytes."""
    if edition not in ("cloud", "enterprise") or not isinstance(raw, bytes) or not 0 < len(raw) <= 1024 * 1024:
        raise ValueError("Invalid edition manifest")
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate manifest key")
            result[key] = value
        return result
    try:
        manifest = json.loads(raw, object_pairs_hook=unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("Malformed edition manifest") from None
    if not isinstance(manifest, dict) or manifest.get("repo") != "tokentimer-" + edition or type(manifest.get("manifestVersion")) is not int or manifest["manifestVersion"] != 1 or not isinstance(manifest.get("core"), dict):
        raise ValueError("Edition manifest identity mismatch")
    field = "testedCommit" if edition == "cloud" else "lastSyncedCoreCommit"
    pin = manifest["core"].get(field)
    if not isinstance(pin, str) or not COMMIT.fullmatch(pin):
        raise ValueError("Invalid edition composition pin")
    return pin


def fetch_edition_pin(edition, commit, token, download):
    """Read a fixed manifest from an exact edition commit via the GitHub API."""
    if edition not in ("cloud", "enterprise") or not isinstance(commit, str) or not COMMIT.fullmatch(commit) or not isinstance(token, str) or not token:
        raise ValueError("Invalid edition fetch identity")
    repo = EDITION_REPOS[edition][0]
    url = f"https://api.github.com/repos/{repo}/contents/compatibility.manifest.json?ref={commit}"
    response = download(url, token)
    if not isinstance(response, bytes) or len(response) > 2 * 1024 * 1024:
        raise ValueError("Invalid manifest response")
    try:
        obj = json.loads(response)
        if not isinstance(obj, dict) or obj.get("type") != "file" or obj.get("path") != "compatibility.manifest.json" or obj.get("encoding") != "base64" or not isinstance(obj.get("content"), str):
            raise ValueError("Unexpected manifest response")
        content = base64.b64decode(obj["content"].replace("\n", ""), validate=True)
    except (UnicodeDecodeError, json.JSONDecodeError, binascii.Error, RecursionError):
        raise ValueError("Malformed manifest response") from None
    return edition_pin_from_manifest(content, edition)


def fetch_qualification_report(edition, commit, run_id, token, download):
    """Collect one exact evidence artifact from its expected GitHub run.

    The existing workflows do not emit this artifact and their qualification for
    final signed packages has not been reviewed; this is not an approval gate.
    The download callback must be the bounded authenticated GitHub API transport.
    """
    if edition not in EDITION_REPOS or not isinstance(commit, str) or not COMMIT.fullmatch(commit) or type(run_id) is not int or run_id < 1 or not isinstance(token, str) or not token:
        raise ValueError("Invalid evidence run identity")
    repo, branch, workflow = EDITION_REPOS[edition]
    endpoint = f"https://api.github.com/repos/{repo}/actions/runs/{run_id}"
    run = json.loads(download(endpoint, token))
    if (not isinstance(run, dict) or run.get("id") != run_id or run.get("status") != "completed" or run.get("conclusion") != "success" or run.get("event") != "workflow_dispatch" or run.get("path") != workflow or run.get("head_branch") != branch or run.get("head_sha") != commit or run.get("repository", {}).get("full_name") != repo or run.get("head_repository", {}).get("full_name") != repo):
        raise ValueError("Untrusted evidence run")
    listing = json.loads(download(endpoint + "/artifacts?per_page=100", token))
    if not isinstance(listing, dict) or type(listing.get("total_count")) is not int or not 0 <= listing["total_count"] <= 100 or not isinstance(listing.get("artifacts"), list) or len(listing["artifacts"]) != listing["total_count"]:
        raise ValueError("Incomplete artifact listing")
    matches = [a for a in listing["artifacts"] if isinstance(a, dict) and a.get("name") == "windows-final-package-qualification"]
    if len(matches) != 1:
        raise ValueError("Final-package evidence artifact unavailable")
    artifact = matches[0]
    if artifact.get("expired") is not False or type(artifact.get("id")) is not int or artifact["id"] < 1 or type(artifact.get("size_in_bytes")) is not int or not 0 < artifact["size_in_bytes"] <= 2 * 1024 * 1024:
        raise ValueError("Invalid evidence artifact identity")
    raw = download(f"https://api.github.com/repos/{repo}/actions/artifacts/{artifact['id']}/zip", token, redirect=True)
    if not isinstance(raw, bytes) or len(raw) > 2 * 1024 * 1024 or artifact.get("digest") != "sha256:" + hashlib.sha256(raw).hexdigest():
        raise ValueError("Evidence artifact integrity mismatch")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            if len(entries) != 1 or entries[0].filename != "qualification.json" or entries[0].is_dir() or entries[0].file_size > 1024 * 1024:
                raise ValueError("Unexpected evidence archive contents")
            payload = archive.read(entries[0])
        def unique_pairs(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Duplicate evidence key")
                result[key] = value
            return result
        report = json.loads(payload, object_pairs_hook=unique_pairs)
    except (zipfile.BadZipFile, RuntimeError, json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        raise ValueError("Malformed evidence artifact") from None
    return {"run": run, "report": report}


def validate_binding(candidate, evidence):
    """Check exact identity and coverage; never return an authorization verdict."""
    if not isinstance(candidate, dict) or set(candidate) != {"sourceCommit", "version", "architectures", "editionCommits", "editionCoreCommits"}:
        raise ValueError("Invalid candidate")
    source = candidate["sourceCommit"]
    if not isinstance(source, str) or not COMMIT.fullmatch(source):
        raise ValueError("Invalid source commit")
    if not isinstance(candidate["version"], str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", candidate["version"]):
        raise ValueError("Invalid version")
    arches = candidate["architectures"]
    if not isinstance(arches, dict) or set(arches) != {"amd64", "arm64"}:
        raise ValueError("Incomplete architecture set")
    for items in arches.values():
        if not isinstance(items, dict) or set(items) != ROLES or any(not isinstance(v, str) or not DIGEST.fullmatch(v) for v in items.values()):
            raise ValueError("Invalid candidate artifact digests")
    editions = candidate["editionCommits"]
    pins = candidate["editionCoreCommits"]
    if not isinstance(editions, dict) or not isinstance(pins, dict) or set(editions) != set(EDITION_REPOS) or set(pins) != set(EDITION_REPOS):
        raise ValueError("Incomplete edition identities")
    if any(not isinstance(v, str) or not COMMIT.fullmatch(v) for v in editions.values()) or any(v != source for v in pins.values()) or editions["core"] != source:
        raise ValueError("Edition composition mismatch")
    required = {(arch, edition) for arch in arches for edition in EDITION_REPOS}
    required |= {(arch, system) for arch in arches for system in NATIVE_SYSTEMS}
    required |= {(arch, "download-command") for arch in arches}
    if not isinstance(evidence, list) or len(evidence) != len(required):
        raise ValueError("Incomplete final-package matrix")
    observed = set()
    for item in evidence:
        if not isinstance(item, dict) or set(item) != {"report", "run"} or not isinstance(item["report"], dict) or not isinstance(item["run"], dict):
            raise ValueError("Invalid evidence")
        report, run = item["report"], item["run"]
        if set(report) != {"slot", "architecture", "sourceCommit", "version", "artifactDigests", "editionCommit", "editionCoreCommit", "status"}:
            raise ValueError("Invalid report fields")
        slot = (report["architecture"], report["slot"])
        if slot not in required or slot in observed:
            raise ValueError("Unexpected or duplicate matrix slot")
        observed.add(slot)
        edition = report["slot"] if report["slot"] in EDITION_REPOS else "core"
        repo, branch, workflow = EDITION_REPOS[edition]
        if (run.get("status") != "completed" or run.get("conclusion") != "success" or run.get("event") != "workflow_dispatch"
                or run.get("path") != workflow or run.get("head_branch") != branch or run.get("head_sha") != editions[edition]
                or run.get("repository", {}).get("full_name") != repo or run.get("head_repository", {}).get("full_name") != repo):
            raise ValueError("Untrusted qualification run")
        if (report["status"] != "passed" or report["sourceCommit"] != source or report["version"] != candidate["version"]
                or report["editionCommit"] != editions[edition] or report["editionCoreCommit"] != pins[edition]
                or report["artifactDigests"] != arches[slot[0]]):
            raise ValueError("Candidate evidence mismatch")
    if observed != required:
        raise ValueError("Incomplete final-package matrix")
    # Existing workflows do not produce authenticated final-package evidence.
    raise NotImplementedError("Final-package evidence producers are not qualified")
