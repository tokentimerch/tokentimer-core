"""Supporting Python/actual-JS proof parity and privacy tests; no native work."""
import copy
import json
from pathlib import Path
import subprocess
import unittest

from certops_retention_policy_expiry import fields, FLAGS, COUNTS, TIMES, SCOPE

ROOT = Path(__file__).resolve().parent.parent


def fixture():
    case = {
        "ownedInterruption": {"scope": "owned-short-retention-native-interruption-drain", "assignedBeforeResume": True, "rootExit86": True, "nativeActiveZero": True, "nativeHandlesClosed": True, "wrapperClosed": True},
        "scope": SCOPE, "configuredRetentionHours": 168,
        "verifiedCutoverAt": "2026-10-15T10:00:00.000Z",
        "oldNotAfter": "2026-10-15T10:02:00.000Z",
        "cleanupDeadline": "2026-10-15T10:07:00.000Z",
        "preDeadlineObservedAt": "2026-10-15T10:01:00.000Z",
        "cleanupObservedAt": "2026-10-15T10:07:01.000Z",
        "waitStartedAt": "2026-10-15T10:01:00.000Z",
        "waitFinishedAt": "2026-10-15T10:07:01.000Z",
        "waitedMonotonicMs": 361000,
        "installedServiceTimerQualified": False, "fullRetentionWindowQualified": False,
        **dict.fromkeys(FLAGS, True), **dict.fromkeys(COUNTS, 2),
    }
    return {"168": case, "720": {**case, "configuredRetentionHours": 720}}


class NativePolicyExpiryProjection(unittest.TestCase):
    def test_projection_matches_actual_javascript_closed_contract(self):
        value = fields(fixture())
        script = "const f=require('./packages/agent/scripts/host/retention-policy-expiry-proof');let s='';process.stdin.on('data',b=>s+=b);process.stdin.on('end',()=>{for(const p of Object.values(JSON.parse(s)))f.verifyProof(p)});"
        subprocess.run(["node", "-e", script], input=json.dumps(value), text=True,
                       cwd=ROOT, check=True, capture_output=True, timeout=20)

    def test_missing_false_coerced_or_promoted_facts_cannot_qualify(self):
        for policy in ("168", "720"):
            for field in fixture()[policy]:
                value = fixture()
                del value[policy][field]
                with self.subTest(policy=policy, missing=field), self.assertRaises(ValueError):
                    fields(value)
            for field in FLAGS + COUNTS:
                for invalid in (False, None, "true", "2"):
                    value = fixture()
                    value[policy][field] = invalid
                    with self.subTest(policy=policy, field=field, invalid=invalid), self.assertRaises(ValueError):
                        fields(value)
            for field in ("installedServiceTimerQualified", "fullRetentionWindowQualified"):
                value = fixture()
                value[policy][field] = True
                with self.assertRaises(ValueError):
                    fields(value)

    def test_temporal_policy_and_map_boundaries(self):
        for change in (
            {"configuredRetentionHours": 720}, {"configuredRetentionHours": "168"},
            {"waitedMonotonicMs": True}, {"waitedMonotonicMs": float("nan")},
            {"waitedMonotonicMs": float("inf")}, {"waitedMonotonicMs": 299999},
            {"waitedMonotonicMs": 600000}, {"waitedMonotonicMs": 320000},
            {"cleanupObservedAt": fixture()["168"]["cleanupDeadline"]},
            {"cleanupDeadline": "2026-10-15T10:06:59.000Z"},
            {"preDeadlineObservedAt": fixture()["168"]["oldNotAfter"]},
            {"waitStartedAt": fixture()["168"]["oldNotAfter"]},
            {"waitFinishedAt": "2026-10-15T10:07:01Z"},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                fields({**fixture(), "168": {**fixture()["168"], **change}})
        for value in (None, {}, {"168": fixture()["168"]}, {**fixture(), "24": fixture()["168"]}):
            with self.assertRaises(ValueError):
                fields(value)
        for field in TIMES:
            value = fixture()
            value["168"][field] = "2026-13-15T10:00:00.000Z"
            with self.assertRaises(ValueError):
                fields(value)

    def test_missing_or_tampered_owned_native_drain_never_qualifies(self):
        for field in fixture()["168"]["ownedInterruption"]:
            value = fixture(); del value["168"]["ownedInterruption"][field]
            with self.subTest(missing=field), self.assertRaises(ValueError): fields(value)
            value = fixture(); value["168"]["ownedInterruption"][field] = False
            with self.subTest(wrong=field), self.assertRaises(ValueError): fields(value)
        value = fixture(); del value["168"]["ownedInterruption"]
        with self.assertRaises(ValueError): fields(value)

    def test_private_native_details_are_stripped_without_mutating_input(self):
        value = fixture()
        value["168"].update(rawNativeInventory="sentinel", cngContainer="private")
        original = copy.deepcopy(value)
        self.assertEqual(fields(value), fixture())
        self.assertEqual(value, original)


if __name__ == "__main__":
    unittest.main()
