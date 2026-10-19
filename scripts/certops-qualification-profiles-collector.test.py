"""Offline scoped evidence parity and promotion refusals; no cloud execution."""
import json
import importlib.util
from pathlib import Path
import subprocess
import unittest
import certops_qualification_profiles as profiles

ROOT=Path(__file__).resolve().parent.parent


class ProfileTests(unittest.TestCase):
    def test_native_adcs_collector_cannot_hide_deferred_scopes_or_promote_full(self):
        spec = importlib.util.spec_from_file_location("adcs_profile_collector", ROOT / "scripts/certops-release-collector.py")
        collector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(collector)
        matrix = json.loads((ROOT / "docs/certops/qualification-suites.json").read_text())
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
        matrix=json.loads((ROOT/"docs/certops/qualification-suites.json").read_text())
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
        matrix=json.loads((ROOT/"docs/certops/qualification-suites.json").read_text())
        for profile in profiles.PROFILES:
            if profile == "extended-adcs":
                with self.assertRaises(ValueError): profiles.select_profile(matrix, profile)
                continue
            expected=profiles.select_profile(matrix,profile)
            result=subprocess.run(["node","-e","const p=require('./scripts/certops-qualification-profiles'),m=require('./docs/certops/qualification-suites.json');const s=p.selectProfile(m,process.argv[1]);console.log(JSON.stringify(p.summaryFields(s,true)));",profile],cwd=ROOT,capture_output=True,text=True,check=True,timeout=30)
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
