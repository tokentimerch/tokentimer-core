import hashlib
import gzip
import importlib.util
import io
import json
import subprocess
from pathlib import Path
import tarfile
import tempfile
import unittest
import sys
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location("generator", Path(__file__).with_name("agent-sbom-generate.py"))
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class GenerationTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.scanner = Path(self.root.name) / "scanner"
        self.validator = Path(self.root.name) / "validator"
        self.scanner.write_bytes(b"scanner fixture")
        self.validator.write_bytes(b"validator fixture")
        node, license_bytes = b"node fixture", b"license fixture"
        z = io.BytesIO()
        with zipfile.ZipFile(z, "w") as archive:
            archive.writestr("node-v24.18.0-win-x64/node.exe", node)
            archive.writestr("node-v24.18.0-win-x64/LICENSE", license_bytes)
        self.upstream = z.getvalue()
        t = io.BytesIO()
        with tarfile.open(fileobj=t, mode="w:gz") as archive:
            for name, data in (("package/runtime/amd64/node.exe", node), ("package/runtime/LICENSE", license_bytes)):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        self.archive = t.getvalue()
        self.policy = {"amd64": ("x64", sha(self.upstream), sha(node))}
        self.calls = []

    def fake_run(self, arguments, **kwargs):
        self.calls.append(arguments)
        self.assertNotIn("NODE_OPTIONS", kwargs["env"])
        if arguments[1] == "scan":
            path = next(arg.split("=", 1)[1] for arg in arguments if arg.startswith("cyclonedx-json@1.6="))
            result = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                      "metadata": {"component": {"type": "file", "version": "sha256:" + sha(self.archive)}}, "components": []}
            Path(path).write_text(json.dumps(result), encoding="utf8")
        return subprocess_result(0)

    def generate(self, **changes):
        args = {"archive": self.archive, "archive_sha": sha(self.archive), "node_zip": self.upstream,
                "architecture": "amd64", "syft": str(self.scanner), "syft_sha": sha(self.scanner.read_bytes()),
                "validator": str(self.validator), "validator_sha": sha(self.validator.read_bytes())}
        args.update(changes)
        with patch.dict(generator.ENRICH.POLICY, self.policy, clear=True), patch.object(generator.subprocess, "run", side_effect=self.fake_run), patch.object(generator, "trusted_temp_parent", return_value=self.root.name), patch.object(generator, "assert_private_workspace"):
            return generator.generate(**args)

    def test_scans_snapshot_enriches_and_validates_same_bytes(self):
        result = json.loads(self.generate())
        self.assertEqual(len(result["components"]), 1)
        self.assertEqual([call[1] for call in self.calls], ["scan", "validate"])
        self.assertNotEqual(self.calls[0][0], str(self.scanner))
        self.assertNotEqual(self.calls[1][0], str(self.validator))

    def test_rejects_wrong_archive_and_tool_pins_before_scanning(self):
        for changes in ({"archive_sha": "0" * 64}, {"syft_sha": "0" * 64}, {"validator_sha": "0" * 64}):
            with self.assertRaises(ValueError): self.generate(**changes)
        self.assertEqual(self.calls, [])

    def test_rejects_concatenated_archive_before_scanner_runs(self):
        unsafe = self.archive + gzip.compress(b"hidden")
        with self.assertRaises(ValueError): self.generate(archive=unsafe, archive_sha=sha(unsafe))
        self.assertEqual(self.calls, [])

    def test_rejects_failed_schema_validation(self):
        original = self.fake_run
        def fail(arguments, **kwargs):
            if arguments[1] == "validate": return subprocess_result(1)
            return original(arguments, **kwargs)
        with patch.dict(generator.ENRICH.POLICY, self.policy, clear=True), patch.object(generator.subprocess, "run", side_effect=fail), patch.object(generator, "trusted_temp_parent", return_value=self.root.name), patch.object(generator, "assert_private_workspace"):
            with self.assertRaises(ValueError):
                generator.generate(self.archive, sha(self.archive), self.upstream, "amd64", str(self.scanner), sha(self.scanner.read_bytes()), str(self.validator), sha(self.validator.read_bytes()))

    def test_rejects_validator_modifying_output(self):
        original = self.fake_run
        def modify(arguments, **kwargs):
            result = original(arguments, **kwargs)
            if arguments[1] == "validate":
                Path(arguments[arguments.index("--input-file") + 1]).write_text("{}", encoding="utf8")
            return result
        with patch.dict(generator.ENRICH.POLICY, self.policy, clear=True), patch.object(generator.subprocess, "run", side_effect=modify), patch.object(generator, "trusted_temp_parent", return_value=self.root.name), patch.object(generator, "assert_private_workspace"):
            with self.assertRaises(ValueError):
                generator.generate(self.archive, sha(self.archive), self.upstream, "amd64", str(self.scanner), sha(self.scanner.read_bytes()), str(self.validator), sha(self.validator.read_bytes()))

    def test_non_linux_refuses_before_tool_execution(self):
        with patch.object(generator.sys, "platform", "win32"), patch.object(generator.subprocess, "run") as run:
            with self.assertRaises(ValueError): generator.trusted_temp_parent()
            run.assert_not_called()

    @unittest.skipUnless(sys.platform == "linux" and hasattr(__import__("os"), "geteuid"), "requires POSIX output semantics")
    def test_output_never_overwrites_existing_file(self):
        output = Path(self.root.name) / "result.json"
        generator.write_new_output(output, b"candidate")
        with self.assertRaises(FileExistsError): generator.write_new_output(output, b"replacement")
        self.assertEqual(output.read_bytes(), b"candidate")

    @unittest.skipUnless(sys.platform == "linux" and hasattr(__import__("os"), "geteuid"), "requires POSIX output semantics")
    def test_output_link_failure_does_not_leave_partial_artifact(self):
        output = Path(self.root.name) / "result.json"
        with patch.object(generator.os, "link", side_effect=OSError("injected")):
            with self.assertRaises(OSError): generator.write_new_output(output, b"candidate")
        self.assertFalse(output.exists())
        self.assertEqual(list(Path(self.root.name).glob(".agent-sbom-output-*")), [])

    @unittest.skipUnless(sys.platform == "linux" and hasattr(__import__("os"), "geteuid"), "requires POSIX output semantics")
    def test_kill_before_or_after_link_never_exposes_partial_output(self):
        module = str(Path(__file__).with_name("agent-sbom-generate.py"))
        script = '''import importlib.util,os,sys
s=importlib.util.spec_from_file_location("g",sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)
link=os.link
def interrupt(*a,**kw):
    if sys.argv[3]=="after": link(*a,**kw)
    os._exit(42)
os.link=interrupt
m.write_new_output(sys.argv[2], b"complete-candidate")
'''
        for point in ("before", "after"):
            output = Path(self.root.name) / (point + ".json")
            result = subprocess.run([sys.executable, "-c", script, module, str(output), point], timeout=15)
            self.assertEqual(result.returncode, 42)
            if point == "before": self.assertFalse(output.exists())
            else: self.assertEqual(output.read_bytes(), b"complete-candidate")


def subprocess_result(code):
    return type("Result", (), {"returncode": code})()


if __name__ == "__main__":
    unittest.main()
