"""Authenticate the original owner of a later retention finalizer report.

Only this fixed workflow may finish on a newer trusted main commit. Native
candidate/source identities stay bound to both independently downloaded sealed
prepare artifacts; orchestrator sources are checked separately against GitHub.
No native action, artifact extraction to disk or cloud mutation occurs here.
"""
import base64
import hashlib
import io
import json
import re
import stat
import zipfile
from datetime import datetime, timedelta

FINALIZER = ".github/workflows/certops-retention24h-finalize.yml"
PREPARE = ".github/workflows/certops-retention24h-prepare.yml"
CONTROLLER_SOURCES = frozenset((
    "scripts/certops-retention24h-azure.js",
    "scripts/certops-retention24h-contract.js",
    "scripts/certops-retention24h-controller.js",
    "scripts/certops-retention24h-proof.js", FINALIZER,
))
SUITE = "windows-domain-adcs-retention24h"
MAX_AUTH_BYTES = 8 * 1024 * 1024
MAX_ZIP = 2 * 1024 * 1024


def require(condition):
    if not condition:
        raise ValueError("Native retention owner authentication failed")


def closed(value, keys):
    require(isinstance(value, dict) and set(value) == set(keys))


def decimal(value):
    require(isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,18}", value))
    return value


def digest(value):
    require(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value))
    return value


def json_bytes(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value)
            value[key] = item
        return value
    def constant(_):
        raise ValueError("Nonfinite retention receipt")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)


def prepared_lease(value):
    closed(value, ("candidateSha", "runId", "runAttempt", "nonce", "vmResourceId", "vmId", "taskName", "nodeSha256", "keeperSha256", "schemaVersion", "kind", "phase", "createdAt", "expiresAt", "hardExpiresAt"))
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1)
    require(value["kind"] == "certops-native-retention24h" and value["phase"] == "preparing")
    require(isinstance(value["candidateSha"], str) and re.fullmatch(r"[a-f0-9]{40}", value["candidateSha"]))
    for key in ("runId", "runAttempt"):
        decimal(value[key])
    for key in ("nonce", "nodeSha256", "keeperSha256"):
        digest(value[key])
    uuid = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
    require(isinstance(value["vmId"], str) and re.fullmatch(uuid, value["vmId"]))
    expected = rf"/subscriptions/{uuid}/resourceGroups/tt-certops-{value['runId']}-{value['runAttempt']}/providers/Microsoft.Compute/virtualMachines/windows-agent"
    require(isinstance(value["vmResourceId"], str) and re.fullmatch(expected, value["vmResourceId"]))
    require(value["taskName"] == "TokenTimer-Retention24h-" + value["nonce"])
    dates = {}
    for key in ("createdAt", "expiresAt", "hardExpiresAt"):
        require(isinstance(value[key], str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", value[key]))
        dates[key] = datetime.fromisoformat(value[key].replace("Z", "+00:00"))
    require(dates["expiresAt"] == dates["createdAt"] + timedelta(hours=4))
    require(dates["hardExpiresAt"] == dates["createdAt"] + timedelta(hours=32))
    return value


def validate_finalizer_run(run, repository, run_id):
    require(type(run_id) is int and run_id > 0)
    require(run.get("id") == run_id and type(run.get("id")) is int)
    require(type(run.get("run_attempt")) is int and run["run_attempt"] > 0)
    require(run.get("status") == "completed" and run.get("conclusion") == "success")
    require(run.get("path") == FINALIZER and run.get("head_branch") == "main")
    require(run.get("event") in ("schedule", "workflow_dispatch"))
    require(run.get("repository", {}).get("full_name") == repository)
    require(run.get("head_repository", {}).get("full_name") == repository)
    require(isinstance(run.get("head_sha"), str) and re.fullmatch(r"[a-f0-9]{40}", run["head_sha"]))


def source_pairs(rows):
    require(isinstance(rows, list) and 1 <= len(rows) <= 96)
    result = {}
    for row in rows:
        closed(row, ("file", "sha256"))
        file = row["file"]
        require(isinstance(file, str) and re.fullmatch(r"[A-Za-z0-9_./-]{1,240}", file))
        require(not file.startswith("/") and ".." not in file.split("/") and file not in result)
        result[file] = digest(row["sha256"])
    return result


def prepare_job(owner, response):
    """Anchor native creation to execution after any protected approval wait."""
    require(isinstance(response, dict) and type(response.get("total_count")) is int and response["total_count"] == 1)
    require(isinstance(response.get("jobs"), list) and len(response["jobs"]) == 1)
    job = response["jobs"][0]
    require(isinstance(job, dict) and job.get("name") == "prepare")
    require(type(job.get("id")) is int and job["id"] > 0)
    require(type(job.get("run_id")) is int and job["run_id"] == owner["id"])
    require(job.get("head_sha") == owner["head_sha"])
    if "run_attempt" in job:
        require(type(job["run_attempt"]) is int and job["run_attempt"] == owner["run_attempt"])
    # This consumer authenticates only completed successful owners. A pending
    # job cannot provide a sealed preparation for release collection.
    require(job.get("status") == "completed" and job.get("conclusion") == "success")
    start, end = timestamp(job.get("started_at")), timestamp(job.get("completed_at"))
    run_created, run_updated = timestamp(owner.get("created_at")), timestamp(owner.get("updated_at"))
    require(run_updated >= run_created and start >= run_created - 5)
    require(start <= end <= run_updated + 5)
    return {"startedAt": start, "completedAt": end, "jobId": str(job["id"])}


def authenticate(report, run, run_id, candidate, repository, fetch):
    """fetch(url, redirect=False) must retain the collector's credential policy.

    Every additional byte is bounded here and also charged by the caller to the
    existing overall collection budget. Candidate filtering happens beforehand.
    """
    validate_finalizer_run(run, repository, run_id)
    require(report.get("candidateSha") == candidate and report.get("suite") == SUITE)
    proof = report.get("nativeRetention24h")
    require(isinstance(proof, dict) and proof.get("candidateSha") == candidate)
    provenance = report.get("retention24hProvenance")
    closed(provenance, ("originalArtifact", "handoffArtifact", "finalizerProvenance"))
    finalizer = provenance["finalizerProvenance"]
    closed(finalizer, ("repository", "runId", "runAttempt", "headSha", "event", "headBranch", "workflowPath", "controllerSources"))
    expected = {"repository": repository, "runId": str(run_id), "runAttempt": str(run["run_attempt"]),
                "headSha": run["head_sha"], "event": run["event"], "headBranch": "main", "workflowPath": FINALIZER}
    for key, value in expected.items():
        require(finalizer.get(key) == value)
    used = 0
    def get(url, redirect=False):
        nonlocal used
        raw = fetch(url, redirect=redirect)
        require(isinstance(raw, bytes))
        used += len(raw)
        require(used <= MAX_AUTH_BYTES)
        return raw
    base = f"https://api.github.com/repos/{repository}"
    controllers = source_pairs(finalizer["controllerSources"])
    require(set(controllers) == CONTROLLER_SOURCES)
    for file, expected_hash in controllers.items():
        data = json_bytes(get(f"{base}/contents/{file}?ref={run['head_sha']}"))
        require(data.get("type") == "file" and data.get("path") == file and data.get("encoding") == "base64")
        require(type(data.get("size")) is int and 0 < data["size"] <= 512 * 1024)
        require(isinstance(data.get("content"), str))
        raw = base64.b64decode(data["content"].replace("\n", "").replace("\r", ""), validate=True)
        require(len(raw) == data["size"] and hashlib.sha256(raw).hexdigest() == expected_hash)
    owner_id, attempt = decimal(proof.get("prepareRunId")), decimal(proof.get("prepareRunAttempt"))
    nonce = digest(proof.get("nonce"))
    owner = json_bytes(get(f"{base}/actions/runs/{owner_id}/attempts/{attempt}"))
    validate_finalizer_owner(owner, candidate, repository, owner_id, attempt)
    job = prepare_job(owner, json_bytes(get(f"{base}/actions/runs/{owner_id}/attempts/{attempt}/jobs?per_page=100")))
    inventory = json_bytes(get(f"{base}/actions/runs/{owner_id}/artifacts?per_page=100"))
    require(type(inventory.get("total_count")) is int and 0 <= inventory["total_count"] <= 100)
    require(isinstance(inventory.get("artifacts"), list) and len(inventory["artifacts"]) == inventory["total_count"])
    def receipt(field, name, member):
        claimed = provenance[field]
        closed(claimed, ("id", "name", "archiveSha256"))
        artifact_id = decimal(claimed["id"])
        require(claimed["name"] == f"{name}-{attempt}-{nonce}")
        wanted_hash = digest(claimed["archiveSha256"])
        matches = [row for row in inventory["artifacts"] if row.get("name") == claimed["name"]]
        require(len(matches) == 1)
        artifact = matches[0]
        require(type(artifact.get("id")) is int and str(artifact["id"]) == artifact_id)
        require(artifact.get("expired") is False and type(artifact.get("size_in_bytes")) is int and 0 < artifact["size_in_bytes"] <= MAX_ZIP)
        require(artifact.get("digest") == "sha256:" + wanted_hash)
        context = artifact.get("workflow_run", {})
        require(type(context.get("id")) is int and str(context["id"]) == owner_id)
        require(context.get("head_sha") == candidate and context.get("head_branch") == "main")
        raw = get(f"{base}/actions/artifacts/{artifact_id}/zip", redirect=True)
        require(0 < len(raw) <= MAX_ZIP and hashlib.sha256(raw).hexdigest() == wanted_hash)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            items = archive.infolist()
            require(len(items) == 1)
            item = items[0]
            require(item.filename == member and not item.is_dir() and not (item.flag_bits & 1))
            require(stat.S_IFMT(item.external_attr >> 16) != stat.S_IFLNK)
            require(0 < item.file_size <= 65536 and item.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED))
            return json_bytes(archive.read(item)), artifact
    original, original_metadata = receipt("originalArtifact", "retention24h-original", "retention24h-original.json")
    handoff, handoff_metadata = receipt("handoffArtifact", "retention24h-prepare-ownership", "retention24h-ownership.json")
    closed(original, ("schemaVersion", "scope", "preparedLease", "configSha256", "observed", "observedAt", "publicPreparation"))
    closed(handoff, ("schemaVersion", "scope", "preparedLease", "lease", "configSha256", "observed", "observedAt", "originalArtifact", "publicPreparation", "actualRequestIds", "fingerprints"))
    require(type(original["schemaVersion"]) is int and original["schemaVersion"] == 1)
    require(type(handoff["schemaVersion"]) is int and handoff["schemaVersion"] == 1)
    require(original["scope"] == "host-verified-original-four-hour-retention24h-not-elapsed-qualified")
    require(handoff["scope"] == "host-verified-retention24h-handoff-not-elapsed-qualified")
    lease = prepared_lease(original["preparedLease"])
    created, expires = timestamp(lease["createdAt"]), timestamp(lease["expiresAt"])
    require(job["startedAt"] - 5 <= created < job["startedAt"] + 4 * 3600 + 5)
    require(timestamp(owner["created_at"]) - 5 <= created <= job["completedAt"] + 5)
    require(created <= timestamp(owner["updated_at"]) + 5)
    require(lease.get("runId") == owner_id and lease.get("runAttempt") == attempt)
    require(lease == handoff["preparedLease"])
    for key in ("candidateSha", "nonce", "vmId", "nodeSha256", "keeperSha256"):
        require(proof.get(key) == lease.get(key))
    require(proof.get("originalCreatedAt") == lease.get("createdAt"))
    extended = handoff["lease"]
    require(isinstance(extended, dict) and extended == {**lease, "phase": "keeper-owned", "expiresAt": lease.get("hardExpiresAt")})
    preparation = original["publicPreparation"]
    require(isinstance(preparation, dict) and preparation == handoff["publicPreparation"])
    require(preparation.get("lease") == lease)
    require(digest(preparation.get("configSha256")) == proof.get("configSha256") == original["configSha256"] == handoff["configSha256"])
    require(isinstance(handoff["observed"], dict))
    for key in ("processId", "processCreatedAt", "bootTime", "taskXmlSha256"):
        require(proof.get(key) == handoff["observed"].get(key))
    require(handoff["originalArtifact"] == provenance["originalArtifact"])
    require(handoff["actualRequestIds"] == preparation.get("actualRequestIds") == proof.get("requestIds"))
    require(handoff["fingerprints"] == preparation.get("fingerprints") == proof.get("fingerprints"))
    generations = preparation.get("generations")
    require(isinstance(generations, list) and len(generations) == 2 and all(isinstance(row, dict) for row in generations))
    for target, key in (("requestIds", "requestId"), ("enrollmentIds", "enrollmentId"), ("jobIds", "jobId"), ("thumbprints", "thumbprint"), ("containerNames", "containerName"), ("spkiSha256", "spkiSha256")):
        require(proof.get(target) == [row.get(key) for row in generations])
    require(proof.get("serialNumbers") == [row.get("serial", "").lower() for row in generations])
    for key in ("verifiedCutoverAt", "oldNotAfter", "cleanupDeadline", "ledgerIdentitySha256"):
        require(proof.get(key) == preparation.get(key))
    require(proof.get("collectorHelperSha256") == preparation.get("collectorHelper", {}).get("sha256"))
    # GitHub artifact timestamps have second precision. Source-level upload
    # ordering remains mandatory; five seconds accounts for API clock precision.
    require(timestamp(original["observedAt"]) <= timestamp(original_metadata.get("created_at")) + 5)
    require(timestamp(original_metadata.get("created_at")) <= timestamp(handoff["observedAt"]) + 5)
    require(timestamp(handoff["observedAt"]) <= timestamp(handoff_metadata.get("created_at")) + 5)
    require(timestamp(original_metadata.get("created_at")) <= timestamp(handoff_metadata.get("created_at")) + 5)
    for value in (original["observedAt"], handoff["observedAt"]):
        require(created <= timestamp(value) < expires)
    for metadata in (original_metadata, handoff_metadata):
        sealed = timestamp(metadata.get("created_at"))
        require(job["startedAt"] - 5 <= sealed <= job["completedAt"] + 5)
        require(created - 5 <= sealed < expires + 5)
    require(source_pairs(report.get("fixtureSources")) == source_pairs(preparation.get("fixtureSources")))
    fixture = report.get("fixtureSource")
    require(isinstance(fixture, dict) and fixture.get("file") == "scripts/certops-retention24h-runtime.js")
    require(source_pairs(report["fixtureSources"]).get(fixture["file"]) == fixture.get("sha256"))
    return True


def timestamp(value):
    require(isinstance(value, str) and len(value) <= 40 and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})", value))
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def validate_finalizer_owner(owner, candidate, repository, owner_id, attempt):
    require(type(owner.get("id")) is int and str(owner["id"]) == owner_id)
    require(type(owner.get("run_attempt")) is int and str(owner["run_attempt"]) == attempt)
    require(owner.get("status") == "completed" and owner.get("conclusion") == "success")
    require(owner.get("path") == PREPARE and owner.get("event") == "workflow_dispatch")
    require(owner.get("head_sha") == candidate and owner.get("head_branch") == "main")
    require(owner.get("repository", {}).get("full_name") == repository)
    require(owner.get("head_repository", {}).get("full_name") == repository)
