"""Guard the intentionally disabled, non-delivering signing preflight."""
from pathlib import Path
import re
import unittest

WORKFLOW = Path(__file__).parent.parent / ".github/workflows/windows-agent-signing-preflight.yml"


def check_safety(text):
    if not re.search(r"(?m)^on:\s*\n\s+workflow_dispatch:\s*\n\s*\npermissions:", text):
        raise ValueError("Unexpected workflow trigger")
    match = re.search(r"(?ms)^  inventory-signing-preflight:\s*\n(.*?)(?=^  [a-z][a-z0-9-]*:\s*$|\Z)", text)
    if not match:
        raise ValueError("Missing signing preflight")
    job = match.group(1)
    requirements = (
        "needs: [build, inventory-binding-preflight]",
        "if: github.event_name == 'workflow_call' && github.repository == 'tokentimerch/tokentimer-core' && github.ref == 'refs/heads/main'",
        "environment: windows-agent-signing",
        "id-token: write",
        "needs.inventory-binding-preflight.outputs.amd64",
        "needs.inventory-binding-preflight.outputs.arm64",
        "generate-pkcs7: true",
        "pkcs7-options: Embedded",
        "pkcs7-oid: 1.2.840.113549.1.7.1",
        "throw 'CMS publisher, timestamp and exact-content verification are not yet qualified; candidate cannot be delivered'",
    )
    if any(value not in job for value in requirements):
        raise ValueError("Signing preflight guard removed")
    if re.search(r"(?i)actions/upload-artifact|gh\s+release|softprops/action-gh-release|\bpublish\b", job):
        raise ValueError("Signing preflight exposes an unqualified output")


class InventoryWorkflowTests(unittest.TestCase):
    def test_disabled_signer_has_no_delivery_path(self):
        check_safety(WORKFLOW.read_text(encoding="utf8"))

    def test_rejects_accidental_trigger_delivery_or_missing_refusal(self):
        text = WORKFLOW.read_text(encoding="utf8")
        for old, new in (("  workflow_dispatch:", "  workflow_call:"),
                         ("throw 'CMS publisher, timestamp and exact-content verification are not yet qualified; candidate cannot be delivered'", "Write-Output OK"),
                         ("pkcs7-options: Embedded", "pkcs7-options: DetachedSignedData"),
                         ("- name: Refuse delivery until independent CMS verification is qualified", "- uses: actions/upload-artifact@somecommit")):
            changed = text.replace(old, new, 1)
            self.assertNotEqual(changed, text)
            with self.subTest(old=old), self.assertRaises(ValueError):
                check_safety(changed)


if __name__ == "__main__":
    unittest.main()
