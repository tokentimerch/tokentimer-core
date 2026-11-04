import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("binding", Path(__file__).with_name("windows-release-evidence.py"))
binding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(binding)


class BindingTests(unittest.TestCase):
    def fixture(self):
        source = "a" * 40
        edition = {"core": source, "cloud": "b" * 40, "enterprise": "c" * 40}
        c = {"sourceCommit": source, "version": "1.2.3", "editionCommits": edition,
             "editionCoreCommits": {name: source for name in edition},
             "architectures": {arch: {role: str(n) * 64 for n, role in enumerate(sorted(binding.ROLES), 1)} for arch in ("amd64", "arm64")}}
        reports = []
        for arch in c["architectures"]:
            for slot in list(binding.EDITION_REPOS) + sorted(binding.NATIVE_SYSTEMS) + ["download-command"]:
                owner = slot if slot in edition else "core"
                repo, branch, workflow = binding.EDITION_REPOS[owner]
                run = {"status": "completed", "conclusion": "success", "event": "workflow_dispatch", "path": workflow,
                       "head_branch": branch, "head_sha": edition[owner], "repository": {"full_name": repo}, "head_repository": {"full_name": repo}}
                report = {"slot": slot, "architecture": arch, "sourceCommit": source, "version": c["version"],
                          "artifactDigests": copy.deepcopy(c["architectures"][arch]), "editionCommit": edition[owner], "editionCoreCommit": source, "status": "passed"}
                reports.append({"report": report, "run": run})
        return c, reports

    def test_complete_matrix_is_only_a_binding_not_publication_approval(self):
        c, e = self.fixture()
        self.assertIsNone(binding.validate_binding(c, e))

    def test_missing_duplicate_or_stale_evidence_is_rejected(self):
        c, e = self.fixture()
        for bad in (e[:-1], [e[0]] + e[1:-1] + [e[0]]):
            with self.assertRaises(ValueError): binding.validate_binding(c, bad)
        for key in ("archive", "checksum", "signature", "sbom", "inventory", "launcher"):
            bad = copy.deepcopy(e)
            bad[0]["report"]["artifactDigests"][key] = "0" * 64
            with self.assertRaises(ValueError): binding.validate_binding(c, bad)
        bad = copy.deepcopy(e)
        bad[0]["report"]["sourceCommit"] = "f" * 40
        with self.assertRaises(ValueError): binding.validate_binding(c, bad)

    def test_fork_wrong_workflow_or_edition_composition_is_rejected(self):
        c, e = self.fixture()
        for key, value in (("path", ".github/workflows/other.yml"), ("head_branch", "feature"), ("conclusion", "failure"), ("head_sha", "f" * 40), ("head_repository", {"full_name": "fork/repo"})):
            bad = copy.deepcopy(e)
            bad[0]["run"][key] = value
            with self.assertRaises(ValueError): binding.validate_binding(c, bad)
        c["editionCoreCommits"]["cloud"] = "f" * 40
        with self.assertRaises(ValueError): binding.validate_binding(c, e)


if __name__ == "__main__":
    unittest.main()
