"""Actual JS stack fixture through main collector, never native execution."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
import certops_acme_stage_proof as proof

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("acme_stage_main_collector", ROOT / "scripts/certops-release-collector.py")
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


def events(scope):
    source = "const a=require('./scripts/test-support/acme-stage-artifact.cjs').artifact(" + json.dumps(scope) + ");process.stdout.write(JSON.stringify(a.events));"
    return json.loads(subprocess.check_output(["node", "-e", source], cwd=ROOT, text=True))


class AcmeStageProjection(unittest.TestCase):
    def test_five_actual_js_stacks_reach_real_projection_with_no_private_outer_data(self):
        for scope in sorted(proof.SCOPES):
            value = events(scope)
            main = next(e for e in value if e["name"] == proof.JOURNEY)
            main["privateLocalState"] = "must-not-survive"
            projected = collector.sanitized_report(value, set(), proof.SCOPES)
            actual = next(e for e in projected if e["name"] == proof.JOURNEY)
            self.assertEqual(actual[proof.FIELD], main[proof.FIELD])
            self.assertNotIn("must-not-survive", json.dumps(projected))

    def test_actual_material_paths_roundtrip_and_strict_scope_limits(self):
        scopes = sorted(proof.SCOPES)
        for scope in scopes:
            value = events(scope)
            projected = collector.sanitized_report(value, set(), proof.SCOPES)
            main = next(e for e in projected if "nativeAcmeKeyReuse" in e)
            check = "const f=require('./scripts/test-support/acme-stage-artifact.cjs'),a=f.artifact(" + json.dumps(scope) + ");a.events=JSON.parse(require('fs').readFileSync(0,'utf8'));const slot=require('./docs/certops/qualification-suites.json').slots.find(x=>x.suite===a.suite);const e=require('./scripts/certops-release-qualification').verifyMatrix([a],{candidateSha:'a'.repeat(40),specification:{schemaVersion:1,slots:[slot]}});if(e.length)throw new Error(e.join(';'));"
            subprocess.run(["node", "-e", check], cwd=ROOT, input=json.dumps(projected), text=True, check=True)
            original = main["nativeAcmeKeyReuse"]["materialPaths"]
            for key, current in original.items():
                for wrong in (None, 1 if type(current) is bool else True):
                    bad = copy.deepcopy(value)
                    next(e for e in bad if "nativeAcmeKeyReuse" in e)["nativeAcmeKeyReuse"]["materialPaths"][key] = wrong
                    with self.assertRaises(ValueError):
                        collector.sanitized_report(bad, set(), proof.SCOPES)
            for key in ("clientExecutablePathQualified", "repositoryOrHookPathQualified", "otherPlatformsQualified"):
                bad = copy.deepcopy(value)
                next(e for e in bad if "nativeAcmeKeyReuse" in e)["nativeAcmeKeyReuse"]["materialPaths"][key] = True
                with self.assertRaises(ValueError):
                    collector.sanitized_report(bad, set(), proof.SCOPES)

    def test_causal_counts_identity_client_and_closed_scope_are_mandatory(self):
        original = next(e for e in events("real-agent-acme-filesystem") if e["name"] == proof.JOURNEY)
        for flag in proof.FLAGS:
            for wrong in (False, 1, None):
                value = copy.deepcopy(original)
                value[proof.FIELD][flag] = wrong
                with self.assertRaises(ValueError):
                    proof.fields(value)
        for mutate in (lambda p: p.update(client="acme.sh"), lambda p: p.update(failureOrigin="actual-ca-response"), lambda p: p.update(rawJws="private"), lambda p: p["cases"][1].update(forwardedFaultRequests=1), lambda p: p["cases"][1].update(validAuthorizationCount=0), lambda p: p["cases"][1].update(certificateId=p["cases"][0]["certificateId"])):
            value = copy.deepcopy(original)
            mutate(value[proof.FIELD])
            with self.assertRaises(ValueError):
                proof.fields(value)


if __name__ == "__main__":
    unittest.main()
