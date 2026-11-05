"""Prepare immutable Windows candidate snapshots; release remains disabled.

This prototype binds each staged byte to the digest used by the qualification
matrix and fetches reports from their fixed GitHub workflows. It neither
authenticates Azure CMS inventories nor authorizes or performs publication.
"""
import importlib.util
import json
from pathlib import Path
from types import MappingProxyType


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


evidence = _load("windows_release_evidence", "windows-release-evidence.py")
snapshot = _load("windows_release_snapshot", "windows-release-snapshot.py")
artifact = _load("windows_release_artifact_binding", "windows-release-artifact-binding.py")
ARCHES = frozenset(("amd64", "arm64"))


def _candidate(value):
    if (not isinstance(value, dict) or set(value) != {"sourceCommit", "version", "architectures", "editionCommits", "editionCoreCommits"}
            or not isinstance(value["sourceCommit"], str) or not evidence.COMMIT.fullmatch(value["sourceCommit"])
            or not isinstance(value["version"], str) or not artifact.VERSION.fullmatch(value["version"])):
        raise ValueError("Invalid candidate identity")
    arches = value["architectures"]
    if not isinstance(arches, dict) or set(arches) != ARCHES:
        raise ValueError("Incomplete candidate architectures")
    for entries in arches.values():
        if (not isinstance(entries, dict) or set(entries) != evidence.ROLES
                or any(not isinstance(v, str) or not evidence.DIGEST.fullmatch(v) for v in entries.values())):
            raise ValueError("Incomplete candidate digests")
    editions, pins = value["editionCommits"], value["editionCoreCommits"]
    if (not isinstance(editions, dict) or not isinstance(pins, dict)
            or set(editions) != set(evidence.EDITION_REPOS) or set(pins) != set(evidence.EDITION_REPOS)
            or any(not isinstance(v, str) or not evidence.COMMIT.fullmatch(v) for v in editions.values())
            or editions["core"] != value["sourceCommit"] or any(v != value["sourceCommit"] for v in pins.values())):
        raise ValueError("Invalid candidate edition pins")


def stage_candidate(directory, candidate, filenames):
    """Snapshot and cross-check all candidate assets; never authorize release."""
    _candidate(candidate)
    # Freeze the qualified identity before reading paths; later caller changes
    # cannot substitute the digests used for the content snapshots.
    metadata = json.dumps(candidate, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf8")
    candidate = json.loads(metadata)
    _candidate(candidate)
    if not isinstance(filenames, dict) or set(filenames) != ARCHES:
        raise ValueError("Incomplete asset mapping")
    if any(not isinstance(filenames[arch], dict) for arch in ARCHES):
        raise ValueError("Incomplete asset mapping")
    filenames = {arch: dict(filenames[arch]) for arch in ARCHES}
    expected, keys = {}, set()
    for arch in ARCHES:
        names = filenames[arch]
        if not isinstance(names, dict) or set(names) != evidence.ROLES:
            raise ValueError("Incomplete asset mapping")
        for role, name in names.items():
            if not isinstance(name, str) or name.lower() in keys:
                raise ValueError("Duplicate asset name")
            keys.add(name.lower())
            expected[name] = candidate["architectures"][arch][role]
    assets = snapshot.snapshot_assets(directory, expected)
    for arch in ARCHES:
        names = filenames[arch]
        archive = assets[names["archive"]]
        sbom = assets[names["sbom"]]
        inventory = assets[names["inventory"]]
        artifact.validate_binding(archive, sbom, inventory, archive_name=names["archive"], sbom_name=names["sbom"],
                                  version=candidate["version"], architecture=arch, source_commit=candidate["sourceCommit"])
        checksum = f'{candidate["architectures"][arch]["archive"]}  {names["archive"]}\n'.encode("ascii")
        if assets[names["checksum"]] != checksum:
            raise ValueError("Archive checksum sidecar mismatch")
    # Serialize metadata so changes to the input dict cannot alter a staged
    # snapshot. Byte values and the returned mapping are immutable.
    names = MappingProxyType({arch: MappingProxyType(dict(filenames[arch])) for arch in ARCHES})
    return metadata, names, assets


def verify_qualification(staged, run_ids, tokens):
    """Collect fixed-workflow reports, then fail closed pending qualification.

    Only run this in a trusted environment. No caller-supplied report or
    approval result is accepted, and this function cannot upload artifacts.
    """
    metadata, names, assets = staged
    candidate = json.loads(metadata)
    _candidate(candidate)
    if not isinstance(tokens, dict) or set(tokens) != set(evidence.EDITION_REPOS) or any(not isinstance(v, str) or not v for v in tokens.values()):
        raise ValueError("Missing scoped qualification credentials")
    slots = set(evidence.EDITION_REPOS) | set(evidence.NATIVE_SYSTEMS) | {"download-command"}
    if not isinstance(run_ids, dict) or set(run_ids) != ARCHES:
        raise ValueError("Incomplete qualification runs")
    for arch in ARCHES:
        if (not isinstance(run_ids[arch], dict) or set(run_ids[arch]) != slots
                or any(type(run) is not int or run < 1 for run in run_ids[arch].values())):
            raise ValueError("Incomplete qualification runs")
    for edition in ("cloud", "enterprise"):
        pin = evidence.fetch_trusted_edition_pin(edition, candidate["editionCommits"][edition], tokens[edition])
        if pin != candidate["sourceCommit"]:
            raise ValueError("Edition composition differs from candidate")
    reports = []
    for arch in sorted(ARCHES):
        for slot in sorted(slots):
            edition = slot if slot in evidence.EDITION_REPOS else "core"
            reports.append(evidence.fetch_trusted_qualification_report(edition, candidate["editionCommits"][edition],
                                                                        run_ids[arch][slot], tokens[edition]))
    evidence.validate_binding(candidate, reports)
    # Independent of the existing evidence module's refusal: replacing that
    # prototype cannot silently enable release without CMS and publisher proof.
    raise NotImplementedError("Signed inventory authentication and final-package producers are not qualified")
