"""Offline provenance checks for the shared release-distribution candidate."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import subprocess
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("distribution_collector", ROOT / "scripts/certops-release-collector.py")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class DistributionCollectorTests(unittest.TestCase):
    def setUp(self):
        original = Path.read_text
        def read_text(path, *args, **kwargs):
            if path == ROOT / "packages/agent/package.json":
                return '{"version":"0.20.0"}'
            return original(path, *args, **kwargs)
        self.version_patch = patch.object(Path, "read_text", read_text)
        self.version_patch.start()
        self.addCleanup(self.version_patch.stop)

    def candidate(self, receipt_patch=None, embedded_patch=None):
        capabilities = collector.linux_distribution_capabilities()
        embedded = {"version": "0.20.0", "capabilities": capabilities, **(embedded_patch or {})}
        source = subprocess.run(["node", "-e", "const b=require('./packages/agent/scripts/build-qualified-capabilities');process.stdout.write(b.renderGeneratedModule(JSON.parse(process.argv[1])))", json.dumps(embedded["capabilities"])], cwd=ROOT, capture_output=True, text=True, check=True).stdout
        files = {
            "package/package.json": json.dumps({"name": "@tokentimer/agent", "version": embedded["version"]}).encode(),
            "package/src/capabilities/qualified-capabilities.generated.js":
                source.encode(),
        }
        content = io.BytesIO()
        with tarfile.open(fileobj=content, mode="w:gz") as tar:
            for name, data in files.items():
                entry = tarfile.TarInfo(name); entry.size = len(data); tar.addfile(entry, io.BytesIO(data))
        package = content.getvalue(); digest = hashlib.sha256(package).hexdigest()
        name = "tokentimer-agent-0.20.0.tgz"
        receipt = {"schemaVersion": 1, "candidateSha": "a" * 40, "archive": name, "sha256": digest,
                   "sourceKind": "workflow-checkout", "buildMode": "release-distribution-candidate", "packageVersion": "0.20.0",
                   "packagerSha256": hashlib.sha256((ROOT / "packages/agent/scripts/pack-release.js").read_bytes()).hexdigest(),
                   "capabilities": capabilities, **(receipt_patch or {})}
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("artifact.json", json.dumps(receipt)); archive.writestr(name, package)
            archive.writestr(name + ".sha256", f"{digest}  {name}\n")
        raw = buffer.getvalue()
        return raw, {"id": 42, "digest": "sha256:" + hashlib.sha256(raw).hexdigest()}, {"artifactId": "42", "packageSha256": digest}

    def test_exact_archive_and_embedded_identity(self):
        raw, artifact, proof = self.candidate()
        collector.authenticate_linux_distribution_archive(raw, artifact, proof, "a" * 40)
        for change in ({"id": 43}, {"digest": "sha256:" + "b" * 64}):
            with self.assertRaises(ValueError): collector.authenticate_linux_distribution_archive(raw, {**artifact, **change}, proof, "a" * 40)
        with self.assertRaises(ValueError): collector.authenticate_linux_distribution_archive(raw, artifact, proof, "b" * 40)
        capabilities = collector.linux_distribution_capabilities()
        for receipt, embedded in (({"capabilities": capabilities[:-1]}, None), ({"packageVersion": "0.19.2"}, None),
                                  ({"buildMode": "linux-staging-candidate"}, None), (None, {"capabilities": capabilities[:-1]}),
                                  (None, {"capabilities": list(reversed(capabilities))}), (None, {"version": "0.19.2"})):
            raw, artifact, proof = self.candidate(receipt, embedded)
            with self.assertRaises(ValueError): collector.authenticate_linux_distribution_archive(raw, artifact, proof, "a" * 40)

    def test_job_attempt_and_all_teardowns_are_required(self):
        run = {"id": 123, "run_attempt": 2, "event": "workflow_dispatch"}
        names = ["release-distribution-candidate", "release-native-vault-cleanup", "release-native-openbao-cleanup",
                 "release-native-linux-staging-vault", "release-native-linux-staging-openbao"]
        jobs = {"total_count": len(names), "jobs": [{"name": name, "run_id": 123, "run_attempt": 2,
                 "status": "completed", "conclusion": "success", "steps": [{"name": "Verify teardown of only the owned host and containers", "conclusion": "success"}]} for name in names]}
        collector.validate_linux_distribution_jobs(run, jobs)
        for patch in ({"run_id": 124}, {"run_attempt": 1}, {"conclusion": "failure"}, {"steps": []}):
            bad = {**jobs, "jobs": [*jobs["jobs"][:1], {**jobs["jobs"][1], **patch}, *jobs["jobs"][2:]]}
            with self.assertRaises(ValueError): collector.validate_linux_distribution_jobs(run, bad)
        with self.assertRaises(ValueError): collector.validate_linux_distribution_jobs(run, {"total_count": 4, "jobs": jobs["jobs"][:4]})
        with self.assertRaises(ValueError): collector.validate_linux_distribution_jobs({**run, "event": "push"}, jobs)

    def test_openbao_staging_is_distinct_and_fail_closed(self):
        facts = {"provider": "openbao-kv2", "artifactId": "42", "packageSha256": "a" * 64,
                 "authenticatedAttempts": 1, "authenticatedReads": 1, "destinationMutations": 0,
                 **{key: True for key in ("installedTreeVerified", "stagedAcrossRestart", "activationBlocked", "destinationUnchanged")}}
        report = {"platform": "linux", "architecture": "x64", "nativeLinuxStagingRestart": facts}
        self.assertEqual(collector.linux_staging_fields(report, "openbao"), facts)
        with self.assertRaises(ValueError): collector.linux_staging_fields(report, "vault")
        with self.assertRaises(ValueError): collector.linux_distribution_proof(facts)


if __name__ == "__main__": unittest.main()
