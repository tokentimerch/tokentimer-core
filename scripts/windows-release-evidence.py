"""Bind a future Windows qualification matrix to the same staged artifacts.

Inputs must come from the trusted GitHub API and already verified artifact ZIPs;
this module does not authenticate reports, validate signatures/SBOMs, retrieve
edition manifests or authorize publication. Existing workflows do not produce
these final-package reports, so this is intentionally not a release gate.
"""
import json
import re

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
    # Explicitly no success result: callers cannot use this as release approval.
