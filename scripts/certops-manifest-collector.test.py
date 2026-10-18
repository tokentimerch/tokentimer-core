"""Cross-language parity for compact source groups; no host execution."""
import json
from pathlib import Path
import subprocess
import unittest
from certops_qualification_manifest import expand, load, load_groups

ROOT = Path(__file__).resolve().parent.parent


class ManifestTests(unittest.TestCase):
    def test_grouped_cases_match_node_without_changing_order(self):
        result = subprocess.run(["node", "-e", "console.log(JSON.stringify(require('./scripts/certops-integration-inventory').groups))"], cwd=ROOT, capture_output=True, text=True, check=True, timeout=30)
        self.assertEqual(load_groups(ROOT / "tests/integration/certops-qualification-groups.json"), json.loads(result.stdout))

    def test_committed_python_and_node_slots_are_identical(self):
        result = subprocess.run(["node", "-e", "console.log(JSON.stringify(require('./scripts/certops-qualification-manifest')))"], cwd=ROOT, capture_output=True, text=True, check=True, timeout=30)
        self.assertEqual(load(ROOT / "docs/certops/qualification-suites.json"), json.loads(result.stdout))

    def test_missing_conflicting_and_malformed_sources_fail_closed(self):
        for value in [
            {"sourceGroups": None}, {"sourceGroups": []},
            {"sourceGroups": {"shared": []}},
            {"sourceGroups": {"shared": [False]}},
            {"sourceGroups": {"shared": ["a", "a"]}},
            {"sourceGroups": {"../shared": ["a"]}},
            {"slots": [{"requiredSourceGroup": "missing"}]},
            {"sourceGroups": {"shared": ["a"]}, "slots": [{"requiredSourceGroup": "shared", "requiredSources": []}]},
        ]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                expand(value)

    def test_environment_references_are_strict_and_independent(self):
        value = {"environmentGroups": {"ubuntu": {"nested": {"version": "24.04"}}}, "slots": [{"environmentGroup": "ubuntu"}, {"environmentGroup": "ubuntu"}]}
        result = expand(value)
        result["slots"][0]["environment"]["nested"]["version"] = "changed"
        self.assertEqual(result["slots"][1]["environment"]["nested"]["version"], "24.04")
        self.assertEqual(value["environmentGroups"]["ubuntu"]["nested"]["version"], "24.04")
        for patch in [
            {"environmentGroups": None}, {"environmentGroups": []},
            {"environmentGroups": {"ubuntu": None}}, {"environmentGroups": {"ubuntu": []}},
            {"environmentGroups": {"ubuntu": {}}}, {"environmentGroups": {"../ubuntu": {"osFamily": "linux"}}},
            {"slots": [{"environmentGroup": "missing"}]},
            {"slots": [{"environmentGroup": "ubuntu", "environment": {}}]},
            {"slots": [{"environmentGroup": ["ubuntu"]}]},
        ]:
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                expand({**value, **patch})

    def test_groups_do_not_share_mutable_arrays(self):
        value = {"sourceGroups": {"shared": ["a"]}, "slots": [{"requiredSourceGroup": "shared"}, {"requiredSourceGroup": "shared"}]}
        result = expand(value)
        result["slots"][0]["requiredSources"].append("b")
        self.assertEqual(result["slots"][1]["requiredSources"], ["a"])
        self.assertIn("sourceGroups", value)
        self.assertEqual(expand({"slots": [{"requiredSources": ["a"]}]}), {"slots": [{"requiredSources": ["a"]}]})


if __name__ == "__main__":
    unittest.main()
