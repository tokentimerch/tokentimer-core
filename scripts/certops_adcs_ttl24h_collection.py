"""Authenticate a separate real-day AD CS campaign before release collection.

The original prepare run and its two immutable artifacts bind the native
candidate. A later main-branch finalizer has separately authenticated controller
sources. This module performs bounded reads only; it grants no resource lease.
Native lifecycle proof validation remains an additional mandatory check.
"""
import base64
import hashlib
import io
import json
import re
import stat
import zipfile
from datetime import datetime, timedelta

from certops_retention24h_collection import json_bytes, timestamp, prepare_job

FINALIZER = ".github/workflows/certops-adcs-ttl24h-finalize.yml"
PREPARE = ".github/workflows/certops-adcs-ttl24h-prepare.yml"
SUITE = "windows-domain-adcs-default-ttl24h"
KIND = "certops-native-adcs-ttl24h"
CONTROLLER_SOURCES = frozenset((
    "scripts/certops-adcs-ttl24h-azure.js",
    "scripts/certops-adcs-ttl24h-contract.js",
    "infra/certops-adcs/ttl24h-ca-observe.ps1",
    "scripts/certops-adcs-ttl24h-proof.js", PREPARE, FINALIZER,
))
MAX_AUTH_BYTES = 8 * 1024 * 1024
MAX_ZIP = 2 * 1024 * 1024
IDENTITIES = ("candidateSha", "runId", "runAttempt", "nonce", "vmResourceId",
              "vmId", "taskName", "nodeSha256", "keeperSha256")
OBSERVED_FLAGS = ("soleAgentStoppedAndDrained", "originalCacheAndJournalUnmodified",
                  "predecessorNativeCustodyVerified", "predecessorTrustedTlsVerified",
                  "deferredUnacceptedNativeCustodyVerified")
OBSERVED_KEYS = (*IDENTITIES, "preparedSha256", "taskXmlSha256", "processId",
                 "processCreatedAt", "bootTime", "principalSid", "taskState",
                 "nativeVerificationStartedAt", "nativeVerificationFinishedAt",
                 "monotonicElapsedMs", *OBSERVED_FLAGS)


def require(condition):
    if not condition:
        raise ValueError("AD CS real-day owner authentication failed")


def closed(value, keys):
    require(isinstance(value, dict) and set(value) == set(keys))


def decimal(value):
    require(isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,19}", value))
    return value


def digest(value):
    require(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value))
    return value


def source_pairs(rows):
    require(isinstance(rows, list) and 1 <= len(rows) <= 128)
    result = {}
    for row in rows:
        closed(row, ("file", "sha256"))
        file = row["file"]
        require(isinstance(file, str) and re.fullmatch(r"(?:scripts|tests|packages|apps|infra|\.github)/[A-Za-z0-9_./-]{1,240}", file))
        require(all(part not in ("", ".", "..") for part in file.split("/")) and file not in result)
        result[file] = digest(row["sha256"])
    return result


def prepared_lease(value):
    closed(value, (*IDENTITIES, "schemaVersion", "kind", "phase", "createdAt", "expiresAt", "hardExpiresAt"))
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1)
    require(value["kind"] == KIND and value["phase"] == "preparing")
    require(isinstance(value["candidateSha"], str) and re.fullmatch(r"[a-f0-9]{40}", value["candidateSha"]))
    for key in ("runId", "runAttempt"):
        decimal(value[key])
    for key in ("nonce", "nodeSha256", "keeperSha256"):
        digest(value[key])
    uuid = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
    require(isinstance(value["vmId"], str) and re.fullmatch(uuid, value["vmId"]))
    expected = rf"/subscriptions/{uuid}/resourceGroups/tt-certops-{value['runId']}-{value['runAttempt']}/providers/Microsoft.Compute/virtualMachines/windows-agent"
    require(isinstance(value["vmResourceId"], str) and re.fullmatch(expected, value["vmResourceId"]))
    require(value["taskName"] == "TokenTimer-AdcsTtl24h-" + value["nonce"])
    dates = {}
    for key in ("createdAt", "expiresAt", "hardExpiresAt"):
        require(isinstance(value[key], str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", value[key]))
        dates[key] = datetime.fromisoformat(value[key].replace("Z", "+00:00"))
    require(dates["expiresAt"] == dates["createdAt"] + timedelta(hours=4))
    require(dates["hardExpiresAt"] == dates["createdAt"] + timedelta(hours=32))
    return value


def validate_finalizer_run(run, repository, run_id):
    require(type(run_id) is int and run_id > 0 and type(run.get("id")) is int and run["id"] == run_id)
    require(type(run.get("run_attempt")) is int and run["run_attempt"] > 0)
    require(run.get("status") == "completed" and run.get("conclusion") == "success")
    require(run.get("path") == FINALIZER and run.get("head_branch") == "main")
    require(run.get("event") in ("schedule", "workflow_dispatch"))
    require(run.get("repository", {}).get("full_name") == repository and run.get("head_repository", {}).get("full_name") == repository)
    require(isinstance(run.get("head_sha"), str) and re.fullmatch(r"[a-f0-9]{40}", run["head_sha"]))


def observed(value, prepared, prepared_hash):
    closed(value, OBSERVED_KEYS)
    lease = prepared["lease"]
    for key in IDENTITIES:
        require(value[key] == lease[key])
    require(value["preparedSha256"] == prepared_hash)
    digest(value["taskXmlSha256"])
    require(value["bootTime"] == prepared["bootTime"])
    require(type(value["processId"]) is int and 0 < value["processId"] <= 0xffffffff)
    require(value["principalSid"] == "S-1-5-18" and value["taskState"] == "Running")
    require(type(value["monotonicElapsedMs"]) is int and 0 <= value["monotonicElapsedMs"] < 4 * 3600000)
    require(all(value[key] is True for key in OBSERVED_FLAGS))
    start, end = timestamp(value["nativeVerificationStartedAt"]), timestamp(value["nativeVerificationFinishedAt"])
    require(timestamp(prepared["preparedAt"]) <= timestamp(value["processCreatedAt"]) <= start <= end < timestamp(lease["expiresAt"]))
    require(end - start <= 300)
    require(timestamp(value["bootTime"]) <= timestamp(value["processCreatedAt"]))


def authenticate(report, run, run_id, candidate, repository, fetch):
    """Use the collector's credential-safe fetch; charge every extra byte there."""
    validate_finalizer_run(run, repository, run_id)
    require(report.get("candidateSha") == candidate and report.get("suite") == SUITE)
    proof = report.get("nativeAdcsTtl24h")
    require(isinstance(proof, dict) and proof.get("candidateSha") == candidate)
    provenance = report.get("adcsTtl24hProvenance")
    closed(provenance, ("originalArtifact", "handoffArtifact", "finalizerProvenance"))
    finalizer = provenance["finalizerProvenance"]
    closed(finalizer, ("repository", "runId", "runAttempt", "headSha", "event", "headBranch", "workflowPath", "controllerSources"))
    expected = dict(repository=repository, runId=str(run_id), runAttempt=str(run["run_attempt"]), headSha=run["head_sha"], event=run["event"], headBranch="main", workflowPath=FINALIZER)
    require(all(finalizer[key] == value for key, value in expected.items()))
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
        require(type(data.get("size")) is int and 0 < data["size"] <= 512 * 1024 and isinstance(data.get("content"), str))
        raw = base64.b64decode(data["content"].replace("\n", "").replace("\r", ""), validate=True)
        require(len(raw) == data["size"] and hashlib.sha256(raw).hexdigest() == expected_hash)
    owner_id, attempt, nonce = decimal(proof.get("prepareRunId")), decimal(proof.get("prepareRunAttempt")), digest(proof.get("nonce"))
    owner = json_bytes(get(f"{base}/actions/runs/{owner_id}/attempts/{attempt}"))
    require(type(owner.get("id")) is int and str(owner["id"]) == owner_id and type(owner.get("run_attempt")) is int and str(owner["run_attempt"]) == attempt)
    require(owner.get("path") == PREPARE and owner.get("event") == "workflow_dispatch" and owner.get("head_branch") == "main" and owner.get("head_sha") == candidate)
    require(owner.get("status") == "completed" and owner.get("conclusion") == "success")
    require(owner.get("repository", {}).get("full_name") == repository and owner.get("head_repository", {}).get("full_name") == repository)
    job = prepare_job(owner, json_bytes(get(f"{base}/actions/runs/{owner_id}/attempts/{attempt}/jobs?per_page=100")))
    inventory = json_bytes(get(f"{base}/actions/runs/{owner_id}/artifacts?per_page=100"))
    require(type(inventory.get("total_count")) is int and 0 <= inventory["total_count"] <= 100)
    require(isinstance(inventory.get("artifacts"), list) and len(inventory["artifacts"]) == inventory["total_count"])
    def receipt(field, kind):
        claimed = provenance[field]
        closed(claimed, ("id", "name", "archiveSha256"))
        artifact_id, wanted_hash = decimal(claimed["id"]), digest(claimed["archiveSha256"])
        require(claimed["name"] == f"adcs-ttl24h-{kind}-{attempt}-{nonce}")
        matches = [row for row in inventory["artifacts"] if row.get("name") == claimed["name"]]
        require(len(matches) == 1)
        artifact = matches[0]
        require(type(artifact.get("id")) is int and str(artifact["id"]) == artifact_id)
        require(artifact.get("expired") is False and type(artifact.get("size_in_bytes")) is int and 0 < artifact["size_in_bytes"] <= MAX_ZIP)
        require(artifact.get("digest") == "sha256:" + wanted_hash)
        context = artifact.get("workflow_run", {})
        require(type(context.get("id")) is int and str(context["id"]) == owner_id and context.get("head_sha") == candidate and context.get("head_branch") == "main")
        raw = get(f"{base}/actions/artifacts/{artifact_id}/zip", redirect=True)
        require(0 < len(raw) <= MAX_ZIP and hashlib.sha256(raw).hexdigest() == wanted_hash)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            items = archive.infolist()
            require(len(items) == 1)
            item = items[0]
            require(item.filename == f"adcs-ttl24h-{kind}.json" and not item.is_dir() and not item.flag_bits & 1)
            require(stat.S_IFMT(item.external_attr >> 16) != stat.S_IFLNK)
            require(0 < item.file_size <= 65536 and item.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED))
            return json_bytes(archive.read(item)), artifact
    original, original_metadata = receipt("originalArtifact", "original")
    handoff, handoff_metadata = receipt("handoffArtifact", "ownership")
    closed(original, ("schemaVersion", "kind", "lease", "publicPreparation", "taskObserved", "controlPlaneObserved", "infrastructureOwnership"))
    closed(handoff, (*original.keys(), "originalArtifact", "handoffObserved"))
    for value in (original, handoff):
        require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["kind"] == KIND)
    lease = prepared_lease(original["lease"])
    require(lease["candidateSha"] == candidate and lease["runId"] == owner_id and lease["runAttempt"] == attempt and lease["nonce"] == nonce)
    created, expires = timestamp(lease["createdAt"]), timestamp(lease["expiresAt"])
    require(job["startedAt"] - 5 <= created < job["startedAt"] + 4 * 3600 + 5 and created <= job["completedAt"] + 5)
    require(handoff["lease"] == {**lease, "phase": "resident-owned", "expiresAt": lease["hardExpiresAt"]})
    prepared = original["publicPreparation"]
    require(isinstance(prepared, dict) and prepared == handoff["publicPreparation"] and prepared.get("lease") == lease)
    closed(prepared, ("scope", "lease", "preparedAt", "bootTime", "chainHelperSha256", "configurationSha256", "apiTrust", "caRequestCounts", "run", "workspaceId", "agentRowId", "issuerId", "confirmedAt", "preflight", "validation", "predecessor", "sources"))
    require(prepared["scope"] == "prepared-real-adcs-ttl24h-not-elapsed-qualified")
    validation = prepared.get("validation")
    require(isinstance(validation, dict) and validation.get("configuredTimeoutSeconds") is None and "configuredTimeoutSeconds" in validation)
    require(validation.get("state") == "validation_deferred")
    require(abs(timestamp(validation.get("deadlineAt")) - timestamp(validation.get("journalUpdatedAt")) - 86400) <= 5)
    require(created <= timestamp(validation["journalUpdatedAt"]) <= timestamp(prepared["preparedAt"]) < expires)
    api_trust = prepared.get("apiTrust")
    closed(api_trust, ("fileId", "sha256", "fingerprint", "notAfter"))
    decimal(api_trust["fileId"])
    digest(api_trust["sha256"])
    digest(api_trust["fingerprint"])
    require(timestamp(api_trust["notAfter"]) > timestamp(lease["hardExpiresAt"]) + 3600)
    prepared_hash = hashlib.sha256((json.dumps(prepared, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")).hexdigest()
    observed(original["taskObserved"], prepared, prepared_hash)
    observed(handoff["handoffObserved"], prepared, prepared_hash)
    require(handoff["taskObserved"] == original["taskObserved"] and handoff["originalArtifact"] == provenance["originalArtifact"])
    for key in ("processId", "processCreatedAt", "bootTime", "taskXmlSha256"):
        require(original["taskObserved"][key] == handoff["handoffObserved"][key] == proof.get(key))
    for key in ("candidateSha", "nonce", "vmId", "nodeSha256", "keeperSha256"):
        require(proof.get(key) == lease[key])
    require(proof.get("originalCreatedAt") == lease["createdAt"] and proof.get("preparedSha256") == prepared_hash)
    # Do not authenticate another enrollment merely because it shares a VM and
    # workflow. Every original native identity must survive the sealed chain.
    for field, expected in {
        "workspaceId": prepared.get("workspaceId"), "agentRowId": prepared.get("agentRowId"),
        "issuerId": prepared.get("issuerId"), "installedEnrollmentId": prepared.get("predecessor", {}).get("enrollmentId"),
        "deferredEnrollmentId": prepared.get("validation", {}).get("enrollmentId"),
        "snapshotSha256": prepared.get("validation", {}).get("snapshotSha256"),
        "deadlineAt": prepared.get("validation", {}).get("deadlineAt"),
    }.items():
        require(expected is not None and proof.get(field) == expected)
    for field, expected in {
        "requestIds": [prepared["predecessor"].get("requestId"), prepared["validation"].get("requestId")],
        "fingerprints": [prepared["predecessor"].get("fingerprint"), prepared["validation"].get("leafFingerprint")],
        "spkiFingerprints": [prepared["predecessor"].get("spkiSha256"), prepared["validation"].get("csrSpkiSha256")],
        "caRequestCounts": [prepared.get("caRequestCounts", {}).get(key) for key in ("before", "installed", "deferred")],
    }.items():
        require(isinstance(proof.get(field), list) and proof[field][:len(expected)] == expected and all(item is not None for item in expected))
    started, finished = timestamp(proof.get("residentStartedAt")), timestamp(proof.get("residentFinishedAt"))
    elapsed, gap, count = proof.get("monotonicElapsedMs"), proof.get("maximumObservationGapMs"), proof.get("keptObservationCount")
    require(type(elapsed) is int and 86400000 <= elapsed <= 90000000 and abs((finished - started) * 1000 - elapsed) <= 5000)
    require(timestamp(prepared["preparedAt"]) <= started <= timestamp(prepared["preparedAt"]) + 600)
    require(timestamp(proof["processCreatedAt"]) <= started < timestamp(prepared["validation"]["deadlineAt"]) - 60)
    require(finished > timestamp(prepared["validation"]["deadlineAt"]) and finished < timestamp(lease["hardExpiresAt"]))
    require(started + 23 * 3600 <= timestamp(proof.get("preDeadlineObservedAt")) < timestamp(prepared["validation"]["deadlineAt"]) - 60)
    require(type(count) is int and 24 <= count <= 26 and type(gap) is int and 0 < gap <= 3900000)
    for value in (prepared.get("preflight", {}).get(key) for key in ("createdAt", "cacheUpdatedAt", "templateCacheUpdatedAt")):
        require(finished > timestamp(value) + 86400)
    control = original["controlPlaneObserved"]
    closed(control, ("resourceId", "vmId", "candidateSha", "observedAt", "composeServices", "containerIds", "noStandaloneCertOpsWorker"))
    require(handoff["controlPlaneObserved"] == control and control["candidateSha"] == candidate)
    require(control["resourceId"] == lease["vmResourceId"].rsplit("/", 1)[0] + "/control-plane")
    require(isinstance(control["vmId"], str) and re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", control["vmId"]) and control["vmId"] != lease["vmId"])
    require(control["composeServices"] == ["api", "mailhog", "postgres"] and control["noStandaloneCertOpsWorker"] is True)
    containers = control["containerIds"]
    require(isinstance(containers, list) and len(containers) == 3)
    services, container_ids = set(), set()
    for item in containers:
        closed(item, ("service", "id"))
        require(item["service"] in control["composeServices"] and item["service"] not in services)
        services.add(item["service"])
        digest(item["id"])
        require(item["id"] not in container_ids)
        container_ids.add(item["id"])
    require(created <= timestamp(control["observedAt"]) < expires)
    infrastructure = original["infrastructureOwnership"]
    require(isinstance(infrastructure, list) and len(infrastructure) == 2 and handoff["infrastructureOwnership"] == infrastructure)
    names, vm_ids = set(), {lease["vmId"]}
    for item in infrastructure:
        closed(item, ("name", "resourceId", "vmId", "createdAt"))
        require(item["name"] in ("domain-ca", "control-plane") and item["name"] not in names)
        names.add(item["name"])
        require(item["resourceId"] == lease["vmResourceId"].rsplit("/", 1)[0] + "/" + item["name"])
        require(isinstance(item["vmId"], str) and re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", item["vmId"]) and item["vmId"] not in vm_ids)
        vm_ids.add(item["vmId"])
        require(job["startedAt"] - 5 <= timestamp(item["createdAt"]) <= job["completedAt"] + 5)
        if item["name"] == "control-plane":
            require(item["resourceId"] == control["resourceId"] and item["vmId"] == control["vmId"])
    first, second = original["taskObserved"], handoff["handoffObserved"]
    require(timestamp(first["nativeVerificationFinishedAt"]) <= timestamp(original_metadata.get("created_at")) + 5)
    require(timestamp(control["observedAt"]) <= timestamp(original_metadata.get("created_at")) + 5)
    require(timestamp(original_metadata.get("created_at")) <= timestamp(second["nativeVerificationStartedAt"]) + 5)
    require(timestamp(second["nativeVerificationFinishedAt"]) <= timestamp(handoff_metadata.get("created_at")) + 5)
    for metadata in (original_metadata, handoff_metadata):
        sealed = timestamp(metadata.get("created_at"))
        require(job["startedAt"] - 5 <= sealed <= job["completedAt"] + 5 and created - 5 <= sealed < expires + 5)
    pairs = source_pairs(prepared.get("sources"))
    require(source_pairs(report.get("fixtureSources")) == pairs)
    fixture = report.get("fixtureSource")
    closed(fixture, ("file", "sha256"))
    require(fixture["file"] == "scripts/certops-adcs-ttl24h-resident.js" and pairs.get(fixture["file"]) == fixture["sha256"])
    return True
