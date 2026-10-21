"""Authenticate original installed-timer ownership across finalizer HEAD drift.

Only this fixed trusted-main finalizer may differ from the native candidate.
Both original prepare artifacts, their bytes, actual prepare job interval and
all original service/observer identities are checked independently. No native
operation or cloud mutation occurs in this collection module.
"""
import base64
import hashlib
import io
import json
import re
import stat
import zipfile
from datetime import datetime

PREPARE = ".github/workflows/certops-retention-cadence-prepare.yml"
FINALIZER = ".github/workflows/certops-retention-cadence-finalize.yml"
SUITE = "windows-domain-installed-retention-default-timer"
KIND = "certops-native-installed-retention-cadence"
SCOPE = "actual-installed-default-six-hour-retention-deferral-timer"
CONTROLLER_SOURCES = frozenset((
    "scripts/certops-retention-cadence-azure.js", "scripts/certops-retention24h-azure.js",
    "scripts/certops-retention-cadence-contract.js", "scripts/certops-retention-cadence-proof.js", FINALIZER,
))
FLAGS = (
    "originalLeaseAndSourcesBound", "realImmediateAtomicLedgerRewrite",
    "realDefaultJitteredAtomicLedgerRewrite", "sameInstalledProcessAndBoot",
    "sameUnmodifiedDefaultConfiguration", "sameDeferredLedgerAndCustody",
    "trustedReplacementTlsPreserved", "independentCurrentNativeReadback", "ownedAzureCleanupVerified",
)
FALSE_FLAGS = (
    "actualCertificateCleanupQualified", "full168HourRetentionQualified",
    "maximum720HourRetentionQualified", "powerLossDurabilityQualified",
)
FACT_FIELDS = (
    "observerProcessId", "observerProcessCreatedAt", "candidateSha", "prepareRunId",
    "prepareRunAttempt", "nonce", "vmId", "nodeSha256", "observerSha256",
    "agentConfigSha256", "observerConfigSha256", "immutableLedgerSha256",
    "pendingLedgerFileId", "immediateLedgerFileId", "timerLedgerFileId", "originalCreatedAt",
    "immediateObservedAt", "timerObservedAt", "finishedAt", "cleanupFinishedAt", "bootTime",
    "serviceHostPid", "serviceHostCreatedAt", "agentPid", "agentCreatedAt",
)
IDENTITY = (
    "candidateSha", "runId", "runAttempt", "nonce", "vmResourceId", "vmId",
    "taskName", "nodeSha256", "observerSha256",
)
OBSERVATION_FLAGS = (
    "taskXmlVerified", "vmIdentityVerified", "observerSourceVerified", "defaultsOmittedVerified",
    "soleInstalledAgentVerified", "soleLedgerWriterVerified", "noOtherActiveJobsVerified",
    "nativeCustodyVerified", "trustedTlsVerified", "immediateSweepVerified",
)
OBSERVATION_FIELDS = (*IDENTITY, *OBSERVATION_FLAGS, "principalSid", "taskState", "processId", "processCreatedAt",
    "bootTime", "serviceHostPid", "serviceHostCreatedAt", "agentPid", "agentCreatedAt", "configSha256",
    "observerConfigSha256", "immutableLedgerSha256", "pendingLedgerFileId", "immediateLedgerFileId",
    "immediateObservedAt", "immediateMonotonicMs", "oldNotAfter", "verifiedAt")
MAX_AUTH_BYTES = 8 * 1024 * 1024
MAX_ZIP = 2 * 1024 * 1024


def require(value):
    if not value:
        raise ValueError("Installed retention timer owner authentication failed")


def closed(value, keys):
    require(isinstance(value, dict) and set(value) == set(keys))


def match(value, pattern):
    require(isinstance(value, str) and re.fullmatch(pattern, value))
    return value


def timestamp(value):
    match(value, r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3,7}Z")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError as error:
        raise ValueError("Invalid installed timer timestamp") from error


def json_bytes(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result)
            result[key] = value
        return result
    def nonfinite(_):
        raise ValueError("Nonfinite installed timer receipt")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=nonfinite)


def source_pairs(rows):
    require(isinstance(rows, list) and 0 < len(rows) <= 128)
    result = {}
    for row in rows:
        closed(row, ("file", "sha256"))
        file = match(row["file"], r"(?:scripts|tests|packages|infra|apps|\.github)/[a-zA-Z0-9_./-]+")
        require(".." not in file.split("/") and file not in result)
        result[file] = match(row["sha256"], r"[a-f0-9]{64}")
    return result


def fields(value):
    """Project measured public facts; arbitrary private fields are discarded."""
    require(isinstance(value, dict) and value.get("scope") == SCOPE)
    require(type(value.get("defaultIntervalMs")) is int and value["defaultIntervalMs"] == 21600000)
    require(type(value.get("defaultRetentionHours")) is int and value["defaultRetentionHours"] == 168)
    require(all(value.get(key) is True for key in FLAGS))
    require(all(value.get(key) is False for key in FALSE_FLAGS))
    elapsed = value.get("actualMonotonicIntervalMs")
    require(type(elapsed) is int and 17280000 - 300000 <= elapsed <= 25920000 + 300000)
    for key in ("observerProcessId", "serviceHostPid", "agentPid"):
        require(type(value.get(key)) is int and 0 < value[key] <= 0xffffffff)
    match(value.get("candidateSha"), r"[a-f0-9]{40}")
    for key in ("prepareRunId", "prepareRunAttempt"):
        match(value.get(key), r"[1-9][0-9]{0,19}")
    for key in ("nonce", "nodeSha256", "observerSha256", "agentConfigSha256", "observerConfigSha256", "immutableLedgerSha256"):
        match(value.get(key), r"[a-f0-9]{64}")
    match(value.get("vmId"), r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}")
    for key in ("pendingLedgerFileId", "immediateLedgerFileId", "timerLedgerFileId"):
        match(value.get(key), r"[1-9][0-9]{0,24}:[1-9][0-9]{0,24}")
    require(value["pendingLedgerFileId"] != value["immediateLedgerFileId"] and value["timerLedgerFileId"] != value["immediateLedgerFileId"])
    times = {key: timestamp(value.get(key)) for key in (
        "observerProcessCreatedAt", "originalCreatedAt", "immediateObservedAt", "timerObservedAt",
        "finishedAt", "cleanupFinishedAt", "bootTime", "serviceHostCreatedAt", "agentCreatedAt",
    )}
    require(times["bootTime"] <= times["observerProcessCreatedAt"] <= times["serviceHostCreatedAt"])
    require(times["bootTime"] <= times["serviceHostCreatedAt"] <= times["agentCreatedAt"] <= times["immediateObservedAt"])
    require(times["originalCreatedAt"] <= times["immediateObservedAt"] < times["timerObservedAt"] <= times["finishedAt"] <= times["cleanupFinishedAt"])
    require(times["immediateObservedAt"] < times["originalCreatedAt"] + 4 * 3600)
    require(times["finishedAt"] <= times["timerObservedAt"] + 300)
    require(times["cleanupFinishedAt"] < times["originalCreatedAt"] + 16 * 3600)
    require(abs((times["timerObservedAt"] - times["immediateObservedAt"]) * 1000 - elapsed) <= 5000)
    return {"scope": SCOPE, "defaultIntervalMs": 21600000, "defaultRetentionHours": 168,
            "actualMonotonicIntervalMs": elapsed, **{key: value[key] for key in FACT_FIELDS},
            **dict.fromkeys(FLAGS, True), **dict.fromkeys(FALSE_FLAGS, False)}


def report_fields(report):
    """Require the native SYSTEM Server measurement before projecting facts."""
    require(report.get("suite") == SUITE and report.get("platform") == "win32" and report.get("architecture") == "x64")
    require(isinstance(report.get("cleanup"), dict) and report["cleanup"].get("status") == "passed")
    expected = {"osFamily": "windows", "osVersion": "2022", "nativeLanguage": "en-US", "identity": "LocalSystem", "measurement": "native", "architecture": "x64"}
    require(report.get("qualificationEnvironment") == expected)
    native = fields(report.get("nativeRetentionCadence"))
    require(native["candidateSha"] == report.get("candidateSha"))
    return native


def validate_finalizer_run(run, repository, run_id):
    require(repository == "tokentimerch/tokentimer-core")
    require(type(run.get("id")) is int and str(run["id"]) == str(run_id))
    require(run.get("status") == "completed" and run.get("conclusion") == "success")
    require(run.get("repository", {}).get("full_name") == repository)
    require(run.get("head_repository", {}).get("full_name") == repository)
    require(run.get("path") == FINALIZER and run.get("head_branch") == "main")
    require(run.get("event") in ("schedule", "workflow_dispatch"))
    match(run.get("head_sha"), r"[a-f0-9]{40}")
    require(type(run.get("run_attempt")) is int and run["run_attempt"] > 0)


def authenticate(report, run, run_id, candidate, repository, fetch):
    validate_finalizer_run(run, repository, run_id)
    require(report.get("suite") == SUITE and report.get("candidateSha") == candidate)
    native = report_fields(report)
    require(native["candidateSha"] == candidate)
    provenance = report.get("retentionCadenceProvenance")
    closed(provenance, ("originalArtifact", "handoffArtifact", "finalizerProvenance"))
    finalizer = provenance["finalizerProvenance"]
    closed(finalizer, ("repository", "runId", "runAttempt", "headSha", "event", "headBranch", "workflowPath", "controllerSources"))
    for key, value in {"repository": repository, "runId": str(run_id), "runAttempt": str(run["run_attempt"]),
                       "headSha": run["head_sha"], "event": run["event"], "headBranch": "main", "workflowPath": FINALIZER}.items():
        require(finalizer[key] == value)
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
    for file, expected in controllers.items():
        item = json_bytes(get(f"{base}/contents/{file}?ref={run['head_sha']}"))
        require(item.get("path") == file and item.get("type") == "file" and item.get("encoding") == "base64")
        require(type(item.get("size")) is int and 0 < item["size"] <= 512 * 1024)
        content = base64.b64decode(item.get("content", ""), validate=False)
        require(len(content) == item["size"] and hashlib.sha256(content).hexdigest() == expected)
    owner_id, attempt, nonce = native["prepareRunId"], native["prepareRunAttempt"], native["nonce"]
    owner = json_bytes(get(f"{base}/actions/runs/{owner_id}/attempts/{attempt}"))
    require(type(owner.get("id")) is int and str(owner["id"]) == owner_id)
    require(type(owner.get("run_attempt")) is int and str(owner["run_attempt"]) == attempt)
    require(owner.get("status") == "completed" and owner.get("conclusion") == "success")
    require(owner.get("repository", {}).get("full_name") == repository and owner.get("head_repository", {}).get("full_name") == repository)
    require(owner.get("path") == PREPARE and owner.get("event") == "workflow_dispatch" and owner.get("head_branch") == "main" and owner.get("head_sha") == candidate)
    job_data = json_bytes(get(f"{base}/actions/runs/{owner_id}/attempts/{attempt}/jobs?per_page=100"))
    require(job_data.get("total_count") == 1 and isinstance(job_data.get("jobs"), list) and len(job_data["jobs"]) == 1)
    job = job_data["jobs"][0]
    require(job.get("name") == "prepare" and job.get("run_id") == owner["id"] and job.get("head_sha") == candidate)
    require(job.get("status") == "completed" and job.get("conclusion") == "success")
    require(type(job.get("id")) is int and job["id"] > 0)
    if "run_attempt" in job:
        require(job["run_attempt"] == owner["run_attempt"])
    started, completed = timestamp(job.get("started_at")), timestamp(job.get("completed_at"))
    require(started <= completed and timestamp(owner.get("created_at")) - 5 <= started)
    inventory = json_bytes(get(f"{base}/actions/runs/{owner_id}/artifacts?per_page=100"))
    require(type(inventory.get("total_count")) is int and inventory["total_count"] <= 100 and isinstance(inventory.get("artifacts"), list))
    def artifact(field, kind):
        claimed = provenance[field]
        closed(claimed, ("id", "name", "archiveSha256"))
        match(claimed["id"], r"[1-9][0-9]{0,19}")
        match(claimed["archiveSha256"], r"[a-f0-9]{64}")
        require(claimed["name"] == f"retention-cadence-{kind}-{attempt}-{nonce}")
        rows = [item for item in inventory["artifacts"] if item.get("name") == claimed["name"]]
        require(len(rows) == 1)
        item = rows[0]
        require(type(item.get("id")) is int and str(item["id"]) == claimed["id"])
        require(item.get("expired") is False and type(item.get("size_in_bytes")) is int and 0 < item["size_in_bytes"] <= MAX_ZIP)
        require(item.get("digest") == "sha256:" + claimed["archiveSha256"])
        require(item.get("workflow_run", {}).get("id") == owner["id"] and item["workflow_run"].get("head_sha") == candidate and item["workflow_run"].get("head_branch") == "main")
        created = timestamp(item.get("created_at"))
        require(started - 5 <= created <= completed + 5)
        raw = get(f"{base}/actions/artifacts/{claimed['id']}/zip", redirect=True)
        require(0 < len(raw) <= MAX_ZIP and hashlib.sha256(raw).hexdigest() == claimed["archiveSha256"])
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist(); require(len(entries) == 1)
            entry = entries[0]
            require(entry.filename == f"retention-cadence-{kind}.json" and not entry.is_dir() and not entry.flag_bits & 1)
            require(stat.S_IFMT(entry.external_attr >> 16) != stat.S_IFLNK)
            require(0 < entry.file_size <= 65536 and entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED))
            return json_bytes(archive.read(entry)), created
    original, original_at = artifact("originalArtifact", "original")
    handoff, handoff_at = artifact("handoffArtifact", "ownership")
    closed(original, ("schemaVersion", "kind", "preparedLease", "preparation", "githubOwner", "azure", "sealedAt"))
    closed(handoff, ("schemaVersion", "kind", "preparedLease", "lease", "preparation", "observed", "originalArtifact", "handedOffAt"))
    require(type(original["schemaVersion"]) is int and original["schemaVersion"] == 1 and original["kind"] == KIND)
    require(type(handoff["schemaVersion"]) is int and handoff["schemaVersion"] == 1 and handoff["kind"] == KIND)
    lease = original["preparedLease"]
    closed(lease, (*IDENTITY, "schemaVersion", "kind", "phase", "createdAt", "expiresAt", "hardExpiresAt"))
    require(lease["schemaVersion"] == 1 and lease["kind"] == KIND and lease["phase"] == "preparing")
    require(lease["candidateSha"] == candidate and lease["runId"] == owner_id and lease["runAttempt"] == attempt and lease["nonce"] == nonce)
    created = timestamp(lease["createdAt"])
    require(started - 5 <= created <= min(started + 3 * 3600 + 5, completed + 5))
    require(timestamp(lease["expiresAt"]) == created + 4 * 3600 and timestamp(lease["hardExpiresAt"]) == created + 16 * 3600)
    require(handoff["preparedLease"] == lease and handoff["lease"] == {**lease, "phase": "observer-owned", "expiresAt": lease["hardExpiresAt"]})
    require(handoff["originalArtifact"] == provenance["originalArtifact"])
    preparation = original["preparation"]
    closed(preparation, ("schemaVersion", "kind", "preparedLease", "observed", "fixtureSources"))
    require(preparation == handoff["preparation"] and preparation["schemaVersion"] == 1 and preparation["kind"] == KIND and preparation["preparedLease"] == lease)
    observed = preparation["observed"]
    closed(observed, OBSERVATION_FIELDS)
    closed(handoff["observed"], OBSERVATION_FIELDS)
    require(all(observed[key] is True for key in OBSERVATION_FLAGS))
    require(observed["principalSid"] == "S-1-5-18" and observed["taskState"] == "Running")
    require(type(observed["immediateMonotonicMs"]) is int and observed["immediateMonotonicMs"] >= 0)
    require(timestamp(observed["oldNotAfter"]) > timestamp(lease["hardExpiresAt"]) + 3600)
    for key in observed:
        if key != "verifiedAt": require(observed[key] == handoff["observed"][key])
    for key in IDENTITY: require(observed.get(key) == lease[key])
    for key in ("candidateSha", "nonce", "vmId", "nodeSha256", "observerSha256"):
        require(native[key] == lease[key])
    require(native["originalCreatedAt"] == lease["createdAt"])
    for target, source in (("observerProcessId", "processId"), ("observerProcessCreatedAt", "processCreatedAt"),
                           ("agentConfigSha256", "configSha256"), ("observerConfigSha256", "observerConfigSha256"),
                           ("immutableLedgerSha256", "immutableLedgerSha256"), ("pendingLedgerFileId", "pendingLedgerFileId"),
                           ("immediateLedgerFileId", "immediateLedgerFileId"), ("immediateObservedAt", "immediateObservedAt"),
                           ("bootTime", "bootTime"), ("serviceHostPid", "serviceHostPid"), ("serviceHostCreatedAt", "serviceHostCreatedAt"),
                           ("agentPid", "agentPid"), ("agentCreatedAt", "agentCreatedAt")):
        require(native[target] == observed.get(source))
    require(created <= timestamp(observed.get("verifiedAt")) <= timestamp(original["sealedAt"]) <= original_at + 5)
    require(original_at - 5 <= timestamp(handoff["observed"].get("verifiedAt")) <= timestamp(handoff["handedOffAt"]) <= handoff_at + 5)
    require(created - 5 <= original_at <= handoff_at < created + 4 * 3600 + 5)
    require(timestamp(handoff["handedOffAt"]) < created + 4 * 3600)
    public_owner = original["githubOwner"]
    closed(public_owner, ("repository", "runId", "runAttempt", "candidateSha", "workflowPath", "event", "headBranch", "jobId", "startedAt", "completedAt"))
    require(public_owner["repository"] == repository and public_owner["workflowPath"] == PREPARE and public_owner["event"] == "workflow_dispatch" and public_owner["headBranch"] == "main")
    require(public_owner["completedAt"] is None or timestamp(public_owner["completedAt"]) == completed)
    require(isinstance(public_owner, dict) and public_owner.get("jobId") == str(job["id"]) and timestamp(public_owner.get("startedAt")) == started)
    require(public_owner.get("runId") == owner_id and public_owner.get("runAttempt") == attempt and public_owner.get("candidateSha") == candidate)
    azure = original["azure"]
    closed(azure, ("groupId", "vmResourceId", "vmId", "vmCreatedAt", "deploymentCreatedAt"))
    match(lease["vmResourceId"], rf"/subscriptions/[a-fA-F0-9-]{{36}}/resourceGroups/tt-certops-{owner_id}-{attempt}/providers/Microsoft.Compute/virtualMachines/windows-agent")
    require(azure["groupId"].lower() == lease["vmResourceId"].split("/providers/")[0].lower())
    require(lease["taskName"] == "TokenTimer-RetentionCadence-" + nonce)
    require(isinstance(azure, dict) and azure.get("vmResourceId") == lease["vmResourceId"] and azure.get("vmId") == native["vmId"])
    for key in ("vmCreatedAt", "deploymentCreatedAt"):
        require(created - 5 <= timestamp(azure.get(key)) <= min(timestamp(observed["verifiedAt"]), started + 3 * 3600 + 5, completed + 5))
    require(len(preparation["fixtureSources"]) > 5)
    pairs = source_pairs(preparation["fixtureSources"])
    require(source_pairs(report.get("fixtureSources")) == pairs)
    closed(report.get("fixtureSource"), ("file", "sha256"))
    require(report["fixtureSource"]["file"] == "scripts/certops-retention-cadence-runtime.js")
    require(pairs.get(report["fixtureSource"]["file"]) == report["fixtureSource"]["sha256"] == native["observerSha256"])
    return True
