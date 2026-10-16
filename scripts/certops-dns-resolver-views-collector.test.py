"""Actual JS proof through real collector; no DNS/provider execution."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
import certops_dns_resolver_views_proof as proof

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("dns_views_collector", ROOT / "scripts/certops-release-collector.py")
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


def report():
    source = "const f=require('./scripts/test-support/dns-resolver-views-artifact.cjs'),h=require('./scripts/certops-dns-resolver-views');const a=f.artifact();h.verifyProof(a.report.nativeResolverViews);process.stdout.write(JSON.stringify(a.report));"
    return json.loads(subprocess.check_output(["node", "-e", source], cwd=ROOT, text=True))


class DnsProjection(unittest.TestCase):
    def test_actual_js_proof_reaches_real_parser_without_private_outer_state(self):
        value = report()
        value["localPrivateState"] = "must-not-survive"
        result = collector.sanitized_report(value, {proof.SUITE}, set())
        self.assertEqual(result[proof.FIELD], value[proof.FIELD])
        self.assertEqual(len(result["fixtureSources"]), 16)
        self.assertNotIn("must-not-survive", json.dumps(result))

    def test_every_observation_and_both_resolver_counts_are_mandatory(self):
        original = report()
        for flag in proof.FLAGS:
            for wrong in (False, 1, None):
                value = copy.deepcopy(original)
                value[proof.FIELD][flag] = wrong
                with self.assertRaises(ValueError):
                    collector.sanitized_report(value, {proof.SUITE}, set())
        for change in ({"scope": "public-recursive-cache"}, {"allForwarded": [2, 0]}, {"quorumForwarded": [1, 0]}, {"rawPackets": "secret"}, {"allAttempts": True}):
            value = copy.deepcopy(original)
            value[proof.FIELD].update(change)
            with self.assertRaises(ValueError):
                proof.project_report(value)


if __name__ == "__main__":
    unittest.main()
