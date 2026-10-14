"""Collect bounded reports from explicitly selected trusted workflow runs.

Invoked by the manual release-collection workflow with a candidate and run IDs.
Checks run provenance and safe artifact boundaries, retains public evidence only,
and delegates qualification to the committed matrix. It neither runs native labs
nor enables AD CS, and experimental/supporting reports cannot fill native slots.
"""
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = {
    ".github/workflows/" + name for name in (
        "certops-qualification.yml", "certops-real-acme.yml",
        "certops-browser-qualification.yml", "certops-kubernetes-qualification.yml",
        "certops-kubernetes-http01-qualification.yml",
        "certops-windows-e2e.yml", "certops-linux-systemd.yml",
        "certops-native-agent-qualification.yml",
        "certops-scheduler-capacity-qualification.yml",
        "certops-renewal-alert-qualification.yml",
        "certops-alpine-acme-qualification.yml",
        "certops-signing-rotation-qualification.yml",
        "certops-enterprise-adcs-qualification.yml",
        "certops-enterprise-adcs-hierarchy-qualification.yml",
        "certops-enterprise-adcs-pending-elapsed.yml",
        "certops-integration-qualification.yml",
        "certops-linux-trust-qualification.yml",
        "certops-filesystem-qualification.yml",
        "certops-nginx-qualification.yml",
        "certops-dns-provider-qualification.yml",
        "certops-dns-routing-qualification.yml",
        "certops-dns-provider-errors.yml",
        "certops-migration-upgrade.yml",
    )
}
MAX_ARCHIVE = 20 * 1024 * 1024
MAX_REPORT = 2 * 1024 * 1024


def catalog_coverage():
    catalog = json.loads((ROOT / "docs/certops/e2e-scenario-catalog.json").read_text())
    rows = catalog.get("scenarios")
    if catalog.get("schemaVersion") != 1 or not isinstance(rows, list) or not rows:
        raise ValueError("Invalid committed scenario catalog")
    counts = {"total": len(rows), "planned": 0, "partial": 0, "implemented": 0}
    for row in rows:
        if row.get("status") not in ("planned", "partial", "implemented"):
            raise ValueError("Invalid catalog implementation status")
        counts[row["status"]] += 1
    return {**counts, "implementationStatus": "all-specifications-implemented" if counts["implemented"] == counts["total"] else "incomplete", "executionEvidence": "reported-separately"}


def validate_matrix_summary(value, candidate, environments, coverage):
    if (not isinstance(value, dict) or value.get("schemaVersion") != 1
            or value.get("status") != "passed" or value.get("candidateSha") != candidate
            or value.get("mandatoryEnvironments") != environments
            or value.get("qualificationScope") != "committed-mandatory-matrix"
            or value.get("allFeaturesQualified") is not False
            or value.get("catalogCoverage") != coverage):
        raise ValueError("Matrix summary cannot promote incomplete feature specifications")


def validate_run(run, candidate, repository):
    if (run.get("status") != "completed" or run.get("conclusion") != "success"
            or run.get("head_sha") != candidate or run.get("head_branch") != "main"
            or run.get("repository", {}).get("full_name") != repository
            or run.get("head_repository", {}).get("full_name") != repository
            or run.get("path") not in WORKFLOWS
            or run.get("event") not in ("push", "workflow_dispatch")):
        raise ValueError("Selected run is not successful trusted-main candidate qualification")


def migration_evidence(value):
    """Retain only bounded public source/schema facts required by its verifier."""
    def text(raw, expression):
        if not isinstance(raw, str) or not re.fullmatch(expression, raw):
            raise ValueError("Invalid public migration identity")
        return raw
    identity = {}
    for kind in ("baseline", "candidate"):
        source = value.get("sourceIdentity", {}).get(kind, {})
        identity[kind] = {
            "sha": text(source.get("sha"), r"[a-f0-9]{40}"),
            "lockfileSha256": text(source.get("lockfileSha256"), r"[a-f0-9]{64}"),
            "version": text(source.get("version"), r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]{1,80})?"),
        }
    result = {"sourceIdentity": identity, "sourceProvenance": text(value.get("sourceProvenance"), r"historical-source-build-to-candidate-source")}
    runtime = value.get("databaseRuntime", {})
    result["databaseRuntime"] = {
        "imageId": text(runtime.get("imageId"), r"sha256:[a-f0-9]{64}"),
        "serverVersion": text(runtime.get("serverVersion"), r"\d+\.\d+(?:\.\d+)?"),
    }
    for name in ("baselineSchema", "candidateSchema"):
        schema = value.get(name, {})
        migrations = schema.get("migrations")
        if not isinstance(migrations, list) or not 0 < len(migrations) <= 4096:
            raise ValueError("Invalid migration inventory size")
        rows = []
        for row in migrations:
            version = row.get("version")
            if not ((type(version) is int and 0 <= version <= 100000) or
                    (isinstance(version, str) and re.fullmatch(r"\d{1,6}", version))):
                raise ValueError("Invalid migration version")
            rows.append({"version": version, "name": text(row.get("name"), r"[A-Za-z0-9_.-]{1,160}")})
        counts = {key: schema.get(key) for key in ("tables", "columns")}
        if any(type(count) is not int or not 0 < count <= 1000000 for count in counts.values()):
            raise ValueError("Invalid schema counts")
        result[name] = {**counts, "migrations": rows}
    for name in ("actualTlsObservedPromotion", "repeatMigrationSchemaUnchanged"):
        if type(value.get(name)) is not bool:
            raise ValueError("Invalid migration transition evidence")
        result[name] = value[name]
    return result


def supporting_sources(value):
    declared = {source for slot in json.loads((ROOT / "docs/certops/release-qualification-matrix.json").read_text())["slots"]
                for source in slot.get("requiredSources", [])}
    if not isinstance(value, list) or len(value) > 32:
        raise ValueError("Invalid supporting source inventory")
    result = []
    for source in value:
        if not isinstance(source, dict) or source.get("file") not in declared:
            continue
        if not isinstance(source.get("sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", source["sha256"]):
            raise ValueError("Invalid supporting source fingerprint")
        result.append({"file": source["file"], "sha256": source["sha256"]})
    return result


def sanitized_report(value, suites, scopes, database_scopes=()):
    if isinstance(value, dict) and value.get("scope") in database_scopes:
        keys = ("scope", "candidateSha", "evidenceLevel", "qualificationEnvironment",
                "fixtureSources", "artifactQualification", "qualificationStatus", "experimental")
        return {**{key: value[key] for key in keys if key in value},
                "tests": [{key: item[key] for key in ("file", "name", "status") if key in item}
                          for item in value.get("tests", []) if isinstance(item, dict)]}
    if isinstance(value, dict) and value.get("suite") in suites:
        keys = ("schemaVersion", "suite", "candidateSha", "startedAt", "finishedAt",
                "status", "strict", "evidenceLevel", "requiredCapabilities",
                "requiredScenarios", "missingCapabilities", "missingScenarios",
                "fixtureSource", "qualificationEnvironment", "artifactQualification", "qualificationStatus", "experimental")
        result = {key: value[key] for key in keys if key in value}
        contract = json.loads((ROOT / "docs/certops/qualification-suites.json").read_text())
        known_ids = contract["suites"].get(value["suite"], [])
        known_caps = contract["requiredCapabilities"].get(value["suite"], [])
        for key, known in (("requiredScenarios", known_ids), ("missingScenarios", known_ids), ("requiredCapabilities", known_caps), ("missingCapabilities", known_caps)):
            if key in result:
                if not isinstance(result[key], list) or len(result[key]) > 4096:
                    raise ValueError("Invalid execution metadata bounds")
                result[key] = [item if isinstance(item, str) and item in known else "[unrecognized]" for item in result[key]]
        result["capabilities"] = {name if name in known_caps else "[unrecognized]": {"available": capability.get("available") is True}
                                  for name, capability in value.get("capabilities", {}).items()
                                  if isinstance(capability, dict)}
        result["scenarios"] = [{key: item[key] for key in
                                ("id", "status", "evidenceLevel", "startedAt", "finishedAt")
                                if key in item} for item in value.get("scenarios", [])
                               if isinstance(item, dict)]
        for scenario in result["scenarios"]:
            if scenario.get("id") not in known_ids:
                scenario["id"] = "[unrecognized]"
            if scenario.get("status") not in ("passed", "failed", "skipped"):
                scenario["status"] = "invalid"
            if scenario.get("evidenceLevel") not in ("unit", "integration", "real-host", "e2e"):
                scenario["evidenceLevel"] = "invalid"
            for key in ("startedAt", "finishedAt"):
                if key in scenario and (not isinstance(scenario[key], str) or not re.fullmatch(r"[0-9TZ:.+\-]{16,40}", scenario[key])):
                    scenario[key] = "invalid"
        if "cleanup" in value:
            result["cleanup"] = {"status": value["cleanup"].get("status")}
        if value.get("suite") == "enterprise-adcs-elapsed-pending-real":
            facts = value.get("nativePendingElapsed")
            if not isinstance(facts, dict):
                raise ValueError("Missing actual pending elapsed evidence")
            bounded = {key: facts.get(key) is True for key in ("snapshotAndCsrStableAcrossRestart", "keyProtectedBeforeDeadline", "signedTerminalCleanup", "exactKeyAbsent", "noCertificateAccepted", "noCaResubmission", "lateApprovalTerminalRefusal", "lateIssuedCertificateRevoked", "outgoingTrustedTlsUnchanged")}
            for key in ("pendingTimeoutSeconds", "pollIntervalSeconds", "monotonicWaitSeconds", "databaseElapsedSeconds"):
                if type(facts.get(key)) not in (int, float) or not 0 <= facts[key] <= 86400:
                    raise ValueError("Invalid pending elapsed counter")
                bounded[key] = facts[key]
            for key in ("databaseDatesRewritten", "journalRewritten"):
                if facts.get(key) is not False:
                    raise ValueError("Pending elapsed state rewritten")
                bounded[key] = False
            for key, pattern in (("pendingSince", r"[0-9TZ:.+\-]{16,40}"), ("requestId", r"[1-9][0-9]{0,9}"), ("snapshotSha256", r"[a-f0-9]{64}")):
                if not isinstance(facts.get(key), str) or not re.fullmatch(pattern, facts[key]):
                    raise ValueError("Invalid pending elapsed identity")
                bounded[key] = facts[key]
            for key, expected in (("clocks", "actual-host-and-database"), ("schedulerClock", "default-real-now"), ("qualificationScope", "configured-one-hour-not-default-fourteen-days")):
                if facts.get(key) != expected:
                    raise ValueError("Invalid pending elapsed scope")
                bounded[key] = expected
            result["nativePendingElapsed"] = bounded
        if value.get("suite") == "windows-native-child-output-privacy":
            for key in ("actualStdoutAndStderrEmission", "actualDelegatedSuccess", "actualAcmeSuccessLogObserved", "actualHttpUploadsSecretFree", "persistedLogsEvidenceResultsSecretFree", "scmConsoleSecretFree"):
                result[key] = value.get(key) is True
            for key, expected in (("actualNativeIdentity", "LocalSystem"), ("childOutputPolicy", "captured-and-withheld-not-live-forwarded"), ("nativeCertificateOutcome", "parent-independent-CNG-IIS-trusted-TLS")):
                if value.get(key) != expected:
                    raise ValueError("Invalid native Windows privacy scope")
                result[key] = expected
            for key in ("receiptCount", "jobLogCount", "evidenceCount", "httpUploadCount"):
                if type(value.get(key)) is not int or not 1 <= value[key] <= (32 if key == "receiptCount" else 10000):
                    raise ValueError("Invalid native Windows privacy counter")
                result[key] = value[key]
        if value.get("suite") == "core-api-migration-upgrade":
            result.update(migration_evidence(value))
        if value.get("suite") in ("enterprise-adcs-real", "enterprise-adcs-hierarchy-real"):
            count = value.get("primaryNativePreflightDispatchCount")
            cohorts = value.get("nativePreflightCohorts")
            if type(count) is not int or not 0 <= count <= 18 or not isinstance(cohorts, list) or len(cohorts) > 128:
                raise ValueError("Invalid native preflight budget evidence")
            result["primaryNativePreflightDispatchCount"] = count
            expiry = value.get("nativeValidationExpiry")
            if not isinstance(expiry, dict):
                raise ValueError("Missing native validation deadline evidence")
            bounded_expiry = {key: expiry.get(key) is True for key in ("actualNativeRevocationUnknown", "actualSignedContinuationExpired", "persistedDeadlineSurvivedRestartAndPolicyRestoration", "exactUnacceptedKeyFreed", "noCertificateAccepted", "noCaResubmission", "outgoingTrustedTlsPreserved", "chainCacheValueRestored")}
            for key in ("configuredTimeoutSeconds", "defaultTimeoutSeconds", "storedWindowSeconds", "monotonicObservedWaitSeconds"):
                if type(expiry.get(key)) not in (int, float) or not 0 <= expiry[key] <= 86400:
                    raise ValueError("Invalid native deadline duration")
                bounded_expiry[key] = expiry[key]
            for key, pattern in (("actualDeadline", r"[0-9TZ:.+\-]{16,40}"), ("requestId", r"[1-9][0-9]{0,9}"), ("snapshotSha256", r"[a-f0-9]{64}")):
                if not isinstance(expiry.get(key), str) or not re.fullmatch(pattern, expiry[key]):
                    raise ValueError("Invalid native deadline identity")
                bounded_expiry[key] = expiry[key]
            if expiry.get("nativeAndCaClocks") != "actual" or expiry.get("qualificationScope") != "configured-five-minute-window-not-default-24-hour-elapsed":
                raise ValueError("Invalid native elapsed deadline scope")
            bounded_expiry.update({"nativeAndCaClocks": "actual", "qualificationScope": "configured-five-minute-window-not-default-24-hour-elapsed"})
            result["nativeValidationExpiry"] = bounded_expiry
            result["nativePreflightCohorts"] = []
            mutations = value.get("nativeTemplateMutations")
            if not isinstance(mutations, list) or len(mutations) > 32:
                raise ValueError("Invalid native template mutation evidence")
            result["nativeTemplateMutations"] = []
            for mutation in mutations:
                if not isinstance(mutation, dict) or any(not isinstance(mutation.get(key), str) or not re.fullmatch(pattern, mutation[key]) for key, pattern in (("caseId", r"[a-z0-9-]{1,100}"), ("template", r"TTQualification[A-Za-z0-9]{1,80}"), ("reason", r"[A-Za-z0-9_-]{1,100}"), ("preflightVerdict", r"unsafe|unreadable|unknown"))):
                    raise ValueError("Invalid bounded template verdict")
                item = {key: mutation[key] for key in ("caseId", "template", "reason", "preflightVerdict")}
                item.update({key: mutation.get(key) is True for key in ("originalConfirmedIssuerReused", "actualSignedJobRefused", "noCaRequestAllocated", "noKeyGenerated", "outgoingTrustedTlsPreserved")})
                result["nativeTemplateMutations"].append(item)
            for cohort in cohorts:
                if not isinstance(cohort, dict) or any(not isinstance(cohort.get(key), str) or not re.fullmatch(r"[a-fA-F0-9-]{36}", cohort[key]) for key in ("workspaceId", "agentId")):
                    raise ValueError("Invalid native preflight cohort identity")
                if type(cohort.get("dispatchCount")) is not int or not 1 <= cohort["dispatchCount"] <= 18 or cohort.get("dispatchLimit") != 18 or cohort.get("nativeIdentity") != "LocalSystem" or cohort.get("runtime") != "candidate-cli":
                    raise ValueError("Invalid native preflight cohort budget")
                result["nativePreflightCohorts"].append({key: cohort[key] for key in ("workspaceId", "agentId", "dispatchCount", "dispatchLimit", "nativeIdentity", "runtime")})
        if "fixtureSources" in value:
            result["fixtureSources"] = supporting_sources(value["fixtureSources"])
        if value.get("suite") == "linux-systemd-writepath":
            evidence = value.get("nativeWritePath", {})
            if not isinstance(evidence, dict):
                raise ValueError("Invalid native systemd evidence")
            result["nativeWritePath"] = {key: evidence.get(key) is True for key in ("freshExecStartPreEvidence", "hostDacWriteVerified", "allowedWrite")}
            result["nativeWritePath"].update({"deniedError": "EROFS" if evidence.get("deniedError") == "EROFS" else "invalid", "samePeerDacMode": "0777" if evidence.get("samePeerDacMode") == "0777" else "invalid", "nonRootUid": evidence.get("nonRootUid") if type(evidence.get("nonRootUid")) is int and 0 < evidence["nonRootUid"] <= 4294967295 else 0})
        if value.get("suite") == "kubernetes-host":
            evidence = value.get("nativeCompaction")
            if not isinstance(evidence, dict):
                raise ValueError("Missing native compaction evidence")
            bounded = {key: evidence.get(key) is True for key in ("productionClient", "productionObserver", "controlPlaneRestarted", "ownedSingleNodeCluster")}
            bounded["expiredStatus"] = 410 if type(evidence.get("expiredStatus")) is int and evidence["expiredStatus"] == 410 else 0
            for key in ("originalResourceVersion", "compactedRevision", "observedResourceVersion"):
                if not isinstance(evidence.get(key), str) or not re.fullmatch(r"[1-9][0-9]{0,19}", evidence[key]):
                    raise ValueError("Invalid compaction revision")
                bounded[key] = evidence[key]
            if not isinstance(evidence.get("certificateUid"), str) or not re.fullmatch(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}", evidence["certificateUid"]):
                raise ValueError("Invalid compaction certificate identity")
            bounded["certificateUid"] = evidence["certificateUid"]
            result["nativeCompaction"] = bounded
        if value.get("suite") == "native-agent-api":
            timing = value.get("nativeDispatchTiming")
            if not isinstance(timing, dict):
                raise ValueError("Missing native dispatch timing evidence")
            bounded_timing = {key: timing.get(key) is True for key in ("nativeClockRefusalObserved", "executionSuccessAbsent", "nonceUnconsumed", "freshClaimRecoverySucceeded", "credentialAndPinUnchanged")}
            for key in ("fixtureLifetimeSeconds", "localToleranceMs", "heldMonotonicMs", "originalDispatchLifetimeSeconds", "leaseCallsBeforeRefusal", "expiredNonceResultStatus"):
                if type(timing.get(key)) not in (int, float) or not 0 <= timing[key] <= 86400000:
                    raise ValueError("Invalid native dispatch timing counter")
                bounded_timing[key] = timing[key]
            for key in ("issuedAt", "expiresAt", "releasedAt"):
                if not isinstance(timing.get(key), str) or not re.fullmatch(r"[0-9TZ:.+\-]{16,40}", timing[key]):
                    raise ValueError("Invalid native dispatch timing date")
                bounded_timing[key] = timing[key]
            for key in ("databaseDatesRewritten", "journalRewritten"):
                if timing.get(key) is not False:
                    raise ValueError("Native dispatch timing state rewritten")
                bounded_timing[key] = False
            for key, expected in (("clocks", "actual-host-monotonic-and-database"), ("fixture", "production-signer-short-lifetime-and-delayed-HTTP-delivery"), ("expiredNonceResultCode", "CERTOPS_AGENT_RESULT_NONCE_REJECTED"), ("actualServerJobState", "claimed"), ("actualRejectedOutbox", "dead-letter"), ("qualificationScope", "native-Linux-shortened-dispatch-fixture-not-stock-TTL-or-Windows-SCM")):
                if timing.get(key) != expected:
                    raise ValueError("Invalid native dispatch timing scope")
                bounded_timing[key] = expected
            result["nativeDispatchTiming"] = bounded_timing
            privacy = value.get("nativeChildOutputPrivacy")
            if not isinstance(privacy, dict) or privacy.get("executedChildren") != 2:
                raise ValueError("Invalid native child output evidence")
            result["nativeChildOutputPrivacy"] = {key: privacy.get(key) is True for key in ("stdoutEmitted", "stderrEmitted", "rawChildOutputWithheld", "genericExecutionMarkerPersisted", "jobSucceeded")}
            result["nativeChildOutputPrivacy"]["executedChildren"] = 2
            rows = value.get("nativeLogFaults")
            if not isinstance(rows, list) or len(rows) > 16:
                raise ValueError("Invalid native log transport evidence")
            known = {name for name in known_ids if name.startswith("native-agent-log-")}
            result["nativeLogFaults"] = []
            for row in rows:
                if not isinstance(row, dict) or row.get("scenario") not in known:
                    raise ValueError("Unknown native log transport scenario")
                item = {"scenario": row["scenario"]}
                item.update({key: row.get(key) is True for key in ("actualNativeConsole", "jobSucceeded", "finalAcknowledged")})
                for key in ("attempts", "persistedLines", "agentGapLines", "serverDroppedLines"):
                    if type(row.get(key)) is not int or not 0 <= row[key] <= 1000:
                        raise ValueError("Invalid native log transport counter")
                    item[key] = row[key]
                result["nativeLogFaults"].append(item)
        if value.get("suite") == "dns-provider-errors":
            inventory = json.loads((ROOT / "docs/certops/dns-provider-errors.json").read_text())
            expected = {(provider["file"], name) for provider in inventory["providers"] + inventory.get("sharedContracts", []) for name in provider["requiredTests"]}
            cases = value.get("dnsAdapterCases")
            if not isinstance(cases, list) or len(cases) > 2048:
                raise ValueError("Invalid DNS adapter case inventory")
            result["dnsAdapterCases"] = [{"file": row["file"], "name": row["name"], "status": row.get("status") if row.get("status") in ("passed", "failed", "skipped") else "invalid"}
                for row in cases if isinstance(row, dict) and (row.get("file"), row.get("name")) in expected]
        return result
    if isinstance(value, list) and value and value[0].get("scope") in scopes:
        keys = ("type", "name", "candidateSha", "scope", "skip", "todo",
                "fixtureSource", "qualificationEnvironment", "artifactQualification", "qualificationStatus", "experimental")
        return [{**{key: event[key] for key in keys if key in event},
                 **({"fixtureSources": supporting_sources(event["fixtureSources"])} if "fixtureSources" in event else {}),
                 "file": event.get("fixtureSource", {}).get("file", "")}
                for event in value]
    return None


def extract_reports(raw, suites, scopes, database_scopes=()):
    if len(raw) > MAX_ARCHIVE:
        raise ValueError("Artifact archive exceeds the bounded download limit")
    reports = []
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        if len(entries) > 500 or sum(item.file_size for item in entries) > 50 * 1024 * 1024:
            raise ValueError("Artifact uncompressed size or entry count exceeds limit")
        for item in entries:
            name = item.filename.replace("\\", "/")
            parts = PurePosixPath(name)
            if parts.is_absolute() or ".." in parts.parts or re.match(r"^[a-zA-Z]:", name) or stat.S_ISLNK(item.external_attr >> 16):
                raise ValueError("Unsafe artifact archive path")
            if item.is_dir() or parts.suffix not in (".json", ".jsonl"):
                continue
            if item.file_size > MAX_REPORT:
                raise ValueError("Qualification report exceeds size limit")
            text = archive.read(item).decode("utf-8")
            try:
                value = json.loads(text) if parts.suffix == ".json" else [json.loads(line) for line in text.splitlines() if line.strip()]
                sanitized = sanitized_report(value, suites, scopes, database_scopes)
            except (ValueError, TypeError, AttributeError):
                raise ValueError("Malformed JSON qualification artifact") from None
            if sanitized is not None:
                reports.append((parts.suffix, sanitized))
    return reports


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def download(url, token=None, redirect=False):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        raise ValueError("Artifact download URL is invalid")
    if token and parsed.hostname != "api.github.com":
        raise ValueError("Authenticated request must stay on GitHub API")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "certops-qualification-collector"}
    if token:
        headers["Authorization"] = "Bearer " + token
    try:
        with urllib.request.build_opener(NoRedirect).open(urllib.request.Request(url, headers=headers), timeout=60) as response:
            raw = response.read(MAX_ARCHIVE + 1)
            if len(raw) > MAX_ARCHIVE:
                raise ValueError("Bounded download exceeded")
            return raw
    except urllib.error.HTTPError as error:
        if redirect and error.code == 302:
            # The signed blob URL receives no GitHub credential.
            return download(error.headers["Location"])
        raise ValueError("Qualification API/download request failed") from None


def main():
    candidate = os.environ.get("CERTOPS_RELEASE_CANDIDATE", "")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    run_ids = json.loads(os.environ.get("CERTOPS_RELEASE_RUN_IDS", "[]"))
    if not re.fullmatch(r"[a-f0-9]{40}", candidate) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not token:
        raise ValueError("Explicit candidate, repository and read-only workflow token required")
    if not isinstance(run_ids, list) or not 1 <= len(run_ids) <= 100 or any(type(item) is not int or item < 1 for item in run_ids) or len(set(run_ids)) != len(run_ids):
        raise ValueError("Run IDs must be a bounded unique JSON array of positive integers")
    matrix = json.loads((ROOT / "docs/certops/release-qualification-matrix.json").read_text())
    suites = {slot["suite"] for slot in matrix["slots"] if slot["kind"] == "host"}
    scopes = {slot["suite"] for slot in matrix["slots"] if slot["kind"] == "stack"}
    database_scopes = {slot["suite"] for slot in matrix["slots"] if slot["kind"] == "database"}
    output = ROOT / "qualification-results/release-collection"
    output.mkdir(parents=True, exist_ok=True)
    files = []
    archive_count = 0
    downloaded_bytes = 0
    coverage = catalog_coverage()
    summary = {"schemaVersion": 1, "candidateSha": candidate, "runIds": run_ids, "status": "failed", "mandatoryEnvironments": len(matrix["slots"]), "collectedReports": 0, "qualificationScope": "committed-mandatory-matrix", "allFeaturesQualified": False, "catalogCoverage": coverage}
    try:
        for run_id in run_ids:
            endpoint = f"https://api.github.com/repos/{repository}/actions/runs/{run_id}"
            validate_run(json.loads(download(endpoint, token)), candidate, repository)
            data = json.loads(download(endpoint + "/artifacts?per_page=100", token))
            if data.get("total_count", 0) > 100:
                raise ValueError("Artifact inventory exceeds explicit bound")
            for artifact in data.get("artifacts", []):
                archive_count += 1
                if archive_count > 200:
                    raise ValueError("Collection artifact count exceeds limit")
                if artifact.get("expired"):
                    raise ValueError("Selected candidate artifact has expired")
                artifact_id = artifact.get("id")
                if type(artifact_id) is not int or artifact.get("size_in_bytes", MAX_ARCHIVE + 1) > MAX_ARCHIVE:
                    raise ValueError("Artifact identity or size is invalid")
                raw = download(f"https://api.github.com/repos/{repository}/actions/artifacts/{artifact_id}/zip", token, redirect=True)
                downloaded_bytes += len(raw)
                if downloaded_bytes > 512 * 1024 * 1024:
                    raise ValueError("Collection total download size exceeds limit")
                for suffix, report in extract_reports(raw, suites, scopes, database_scopes):
                    if len(files) >= 200:
                        raise ValueError("Collection qualification report count exceeds limit")
                    destination = output / f"report-{run_id}-{artifact_id}-{len(files)}{suffix}"
                    destination.write_text(json.dumps(report) if suffix == ".json" else "\n".join(json.dumps(item) for item in report), encoding="utf-8")
                    files.append(str(destination))
        summary["collectedReports"] = len(files)
        if not files:
            raise ValueError("No mandatory qualification reports collected")
        environment = {**os.environ, "GITHUB_SHA": candidate}
        result = subprocess.run(["node", "scripts/certops-release-qualification.js", candidate, *files], cwd=ROOT, env=environment, capture_output=True, text=True, timeout=180)
        if result.returncode != 0:
            # Report identities and bounded verdicts are useful; raw artifacts
            # and subprocess diagnostics are not copied into the summary.
            raise ValueError("Mandatory release matrix qualification failed")
        validate_matrix_summary(json.loads(result.stdout), candidate, len(matrix["slots"]), coverage)
        summary["status"] = "passed"
    finally:
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print("Committed mandatory matrix passed; full feature specifications remain separately tracked")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Even argument/download failures produce a sanitized failed verdict;
        # an older local summary must never look like the current result.
        output = ROOT / "qualification-results/release-collection"
        output.mkdir(parents=True, exist_ok=True)
        candidate = os.environ.get("CERTOPS_RELEASE_CANDIDATE", "")
        (output / "summary.json").write_text(json.dumps({"schemaVersion": 1, "candidateSha": candidate if re.fullmatch(r"[a-f0-9]{40}", candidate) else None, "status": "failed", "qualificationScope": "committed-mandatory-matrix", "allFeaturesQualified": False}, indent=2) + "\n", encoding="utf-8")
        print(str(error) if isinstance(error, ValueError) else "Qualification collection failed", file=sys.stderr)
        sys.exit(1)
