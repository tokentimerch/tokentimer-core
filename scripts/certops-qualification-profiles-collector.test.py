"""Offline scoped evidence parity and promotion refusals; no cloud execution."""
import certops_qualification_manifest as qualification_manifest
import hashlib
import io
import json
import importlib.util
from pathlib import Path
import subprocess
import unittest
import zipfile
import certops_qualification_profiles as profiles

ROOT=Path(__file__).resolve().parent.parent


class ProfileTests(unittest.TestCase):
    def test_openbao_cleanup_binds_its_own_archive_and_receipt(self):
        spec = importlib.util.spec_from_file_location("openbao_profile_collector", ROOT / "scripts/certops-release-collector.py")
        collector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(collector)
        candidate = "a" * 40
        package = b"candidate package"
        digest = hashlib.sha256(package).hexdigest()
        name = "tokentimer-agent-linux-0.19.2-rc.1.tgz"
        capabilities = json.loads((ROOT / "packages/agent/src/capabilities/qualified-capabilities.json").read_text())["qualified"]
        receipt = {"schemaVersion": 1, "candidateSha": candidate, "archive": name, "sha256": digest,
                   "sourceKind": "workflow-checkout", "buildMode": "linux-openbao-cleanup-candidate",
                   "capabilities": capabilities + ["material-cleanup-openbao-kv2-v1"]}
        proof = {"artifactId": "42", "packageSha256": digest}
        def archive():
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as target:
                target.writestr("artifact.json", json.dumps(receipt))
                target.writestr(name, package)
                target.writestr(name + ".sha256", f"{digest}  {name}\n")
            raw = buffer.getvalue()
            return raw, {"id": 42, "digest": "sha256:" + hashlib.sha256(raw).hexdigest()}
        raw, metadata = archive()
        collector.authenticate_vault_archive(raw, metadata, proof, candidate, "openbao")
        for bad in ({**receipt, "buildMode": "linux-vault-cleanup-candidate"},
                    {**receipt, "capabilities": capabilities + ["material-cleanup-vault-kv2-v1"]},
                    {**receipt, "candidateSha": "b" * 40}):
            old = receipt.copy(); receipt.clear(); receipt.update(bad)
            bad_raw, bad_metadata = archive()
            with self.assertRaises(ValueError):
                collector.authenticate_vault_archive(bad_raw, bad_metadata, proof, candidate, "openbao")
            receipt.clear(); receipt.update(old)
        with self.assertRaises(ValueError):
            collector.authenticate_vault_archive(raw, {**metadata, "id": 43}, proof, candidate, "openbao")
        with self.assertRaises(ValueError):
            collector.validate_report_workflow({"suite": collector.OPENBAO_CLEANUP_SUITE}, collector.CI_WORKFLOW)

    def test_linux_staging_requires_the_matching_profile_capability_and_closed_activation(self):
        spec = importlib.util.spec_from_file_location("staging_profile_collector", ROOT / "scripts/certops-release-collector.py")
        collector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(collector)
        candidate, package = "a" * 40, b"fixture staging archive bytes"
        digest = hashlib.sha256(package).hexdigest()
        name = "tokentimer-agent-linux-0.19.2-rc.1.tgz"
        proof = {"artifactId": "42", "packageSha256": digest, "provider": "vault-kv2", "authenticatedAttempts": 1,
                 "authenticatedReads": 1, "destinationMutations": 0,
                 "installedTreeVerified": True, "stagedAcrossRestart": True, "activationBlocked": True, "destinationUnchanged": True}
        report = {"suite": collector.LINUX_STAGING_SUITE, "platform": "linux", "architecture": "x64",
                  "nativeLinuxStagingRestart": proof}
        self.assertEqual(collector.linux_staging_fields(report), proof)
        collector.validate_report_workflow(report, collector.VAULT_CLEANUP_WORKFLOW)
        with self.assertRaises(ValueError):
            collector.validate_report_workflow(report, collector.CI_WORKFLOW)
        for invalid in ({"activationBlocked": False}, {"authenticatedReads": 0}, {"destinationMutations": 1}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                collector.linux_staging_fields({**report, "nativeLinuxStagingRestart": {**proof, **invalid}})
        baseline = json.loads((ROOT / "packages/agent/src/capabilities/qualified-capabilities.json").read_text(encoding="utf-8"))["qualified"]
        for capability in ("material-consumer-staging-v1", "material-cleanup-vault-kv2-v1"):
            with self.subTest(capability=capability):
                receipt = {"schemaVersion": 1, "candidateSha": candidate, "archive": name, "sha256": digest,
                           "sourceKind": "workflow-checkout", "buildMode": "linux-staging-candidate", "capabilities": [*baseline, capability]}
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, "w") as archive:
                    archive.writestr("artifact.json", json.dumps(receipt))
                    archive.writestr(name, package)
                    archive.writestr(name + ".sha256", f"{digest}  {name}\n")
                raw = buffer.getvalue()
                metadata = {"id": 42, "digest": "sha256:" + hashlib.sha256(raw).hexdigest()}
                if capability == "material-consumer-staging-v1":
                    collector.authenticate_vault_archive(raw, metadata, proof, candidate, staging=True)
                else:
                    with self.assertRaises(ValueError):
                        collector.authenticate_vault_archive(raw, metadata, proof, candidate, staging=True)
                with self.assertRaises(ValueError):
                    collector.authenticate_vault_archive(raw, metadata, proof, candidate)

    def test_vault_cleanup_binds_exact_artifact_and_package_bytes(self):
        spec = importlib.util.spec_from_file_location("vault_profile_collector", ROOT / "scripts/certops-release-collector.py")
        collector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(collector)
        candidate = "a" * 40
        package = b"fixture archive bytes"
        digest = hashlib.sha256(package).hexdigest()
        name = "tokentimer-agent-linux-0.19.2-rc.1.tgz"
        proof = {"artifactId": "42", "packageSha256": digest}
        receipt = {"schemaVersion": 1, "candidateSha": candidate, "archive": name, "sha256": digest,
                   "sourceKind": "workflow-checkout", "buildMode": "linux-vault-cleanup-candidate"}

        def artifact(payload):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr("artifact.json", json.dumps(receipt))
                archive.writestr(name, payload)
                archive.writestr(name + ".sha256", f"{digest}  {name}\n")
            raw = buffer.getvalue()
            return raw, {"id": 42, "digest": "sha256:" + hashlib.sha256(raw).hexdigest()}

        raw, metadata = artifact(package)
        collector.authenticate_vault_archive(raw, metadata, proof, candidate)
        with self.assertRaises(ValueError):
            collector.authenticate_vault_archive(raw, {**metadata, "id": 43}, proof, candidate)
        with self.assertRaises(ValueError):
            collector.authenticate_vault_archive(raw, {**metadata, "digest": "sha256:" + "b" * 64}, proof, candidate)
        with self.assertRaises(ValueError):
            collector.authenticate_vault_archive(raw, metadata, proof, "b" * 40)
        changed_raw, changed_metadata = artifact(b"other archive bytes")
        with self.assertRaises(ValueError):
            collector.authenticate_vault_archive(changed_raw, changed_metadata, proof, candidate)
        with self.assertRaises(ValueError):
            collector.validate_report_workflow({"suite": collector.VAULT_CLEANUP_SUITE}, collector.CI_WORKFLOW)

    def test_native_adcs_collector_cannot_hide_deferred_scopes_or_promote_full(self):
        spec = importlib.util.spec_from_file_location("adcs_profile_collector", ROOT / "scripts/certops-release-collector.py")
        collector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(collector)
        matrix = qualification_manifest.load(ROOT / ".github/maintainers/certops/qualification-suites.json")
        selected = profiles.select_profile(matrix, "adcs-native")
        self.assertEqual({row["suite"] for row in selected["specification"]["slots"]}, profiles.ADCS_NATIVE)
        candidate, coverage = "a" * 40, {"implementationStatus": "incomplete"}
        count = len(selected["selectedSlotIds"])
        summary = {"schemaVersion": 1, "status": "passed", "candidateSha": candidate, "mandatoryEnvironments": count, "allFeaturesQualified": False, "catalogCoverage": coverage, **profiles.summary_fields(selected, True)}
        collector.validate_matrix_summary(summary, candidate, count, coverage, selected)
        for patch in ({"fullMatrixQualified": True}, {"qualificationProfile": "full"}, {"omittedSlotIds": []}, {"selectedSlotIds": selected["selectedSlotIds"][:-1]}, {"mandatoryEnvironments": count - 1}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                collector.validate_matrix_summary({**summary, **patch}, candidate, count, coverage, selected)

    def test_actual_collector_rejects_scoped_promotion_and_omission_forgery(self):
        spec=importlib.util.spec_from_file_location("profile_collector",ROOT/"scripts/certops-release-collector.py")
        collector=importlib.util.module_from_spec(spec);spec.loader.exec_module(collector)
        matrix=qualification_manifest.load(ROOT/".github/maintainers/certops/qualification-suites.json")
        selected=profiles.select_profile(matrix,"standard-hosted")
        candidate="a"*40;coverage={"implementationStatus":"incomplete"}
        summary={"schemaVersion":1,"status":"passed","candidateSha":candidate,"mandatoryEnvironments":len(selected["selectedSlotIds"]),"allFeaturesQualified":False,"catalogCoverage":coverage,**profiles.summary_fields(selected,True)}
        collector.validate_matrix_summary(summary,candidate,len(selected["selectedSlotIds"]),coverage,selected)
        failed=collector.failed_profile_summary(["--profile","standard-hosted"],{"CERTOPS_RELEASE_CANDIDATE":candidate})
        self.assertEqual(failed["qualificationProfile"],"standard-hosted");self.assertEqual(failed["selectedSlotIds"],selected["selectedSlotIds"]);self.assertFalse(failed["fullMatrixQualified"]);self.assertEqual(failed["status"],"failed")
        self.assertEqual(collector.failed_profile_summary(["--profile","unknown"],{})["qualificationProfile"],"invalid")
        for patch in ({"fullMatrixQualified":True},{"fullMatrixQualified":0},{"selectedSlotIds":[]},{"omittedSlotIds":[]},{"qualificationProfile":"full"},{"qualificationScope":"committed-mandatory-matrix"}):
            with self.assertRaises(ValueError):collector.validate_matrix_summary({**summary,**patch},candidate,len(selected["selectedSlotIds"]),coverage,selected)

    def test_committed_javascript_python_scope_parity(self):
        matrix=qualification_manifest.load(ROOT/".github/maintainers/certops/qualification-suites.json")
        for profile in profiles.PROFILES:
            expected=profiles.select_profile(matrix,profile)
            result=subprocess.run(["node","-e","const p=require('./scripts/certops-qualification-profiles'),m=require('./scripts/certops-qualification-manifest');const s=p.selectProfile(m,process.argv[1]);console.log(JSON.stringify(p.summaryFields(s,true)));",profile],cwd=ROOT,capture_output=True,text=True,check=True,timeout=30)
            self.assertEqual(json.loads(result.stdout),profiles.summary_fields(expected,True))
            if profile!="full":self.assertFalse(profiles.summary_fields(expected,True)["fullMatrixQualified"])

    def test_unknown_empty_duplicate_and_new_domain_refused(self):
        for profile in ("",None,"hosted","full "):
            with self.assertRaises(ValueError):profiles.select_profile({"slots":[{"id":"one","suite":"fixture"}]},profile)
        for matrix in ({"slots":[]},{"slots":[{"id":"one"},{"id":"one"}]}):
            with self.assertRaises(ValueError):profiles.select_profile(matrix)
        with self.assertRaises(ValueError):profiles.select_profile({"slots":[{"id":"new","suite":"new-domain"}]},"standard-hosted",{"new-domain":["domain"]})
        self.assertEqual(profiles.requested_profile([],{}),"full")
        self.assertEqual(profiles.requested_profile(["--profile","adcs"],{"CERTOPS_QUALIFICATION_PROFILE":"adcs"}),"adcs")
        for args,env in ((["--profile"],{}),(["--profile","adcs"],{"CERTOPS_QUALIFICATION_PROFILE":"full"}),([],{"CERTOPS_QUALIFICATION_PROFILE":""})):
            with self.assertRaises(ValueError):profiles.requested_profile(args,env)


if __name__=="__main__":unittest.main()
