"""Closed installed-systemd discovery projection. Performs no native actions."""
import copy
import re

SUITE = "linux-installed-file-discovery"
FIELD = "nativeInstalledFileDiscovery"
FLAGS = "actualInstalledCandidate actualSystemdService actualUnprivilegedProcess twoGenuinePublicScans publicInventoryExactLocation privateDecoysNeverPersisted credentialAndPinPreserved originalConfigIdentityRestored discoveryProcessDrained restoredServiceAuthenticatedHeartbeat ownedInputsRemoved".split()


def require(condition):
    if not condition:
        raise ValueError("Invalid installed Linux discovery proof")


def project_report(value):
    require(isinstance(value, dict) and value.get("suite") == SUITE)
    require(value.get("platform") == "linux" and value.get("architecture") == "x64")
    environment = value.get("qualificationEnvironment")
    require(isinstance(environment, dict) and environment.get("measurement") == "native" and environment.get("osFamily") == "linux" and environment.get("distributionId") == "ubuntu" and environment.get("distributionVersion") in ("22.04", "24.04") and environment.get("executionSurface") == "host")
    proof = value.get(FIELD)
    require(isinstance(proof, dict) and set(proof) == {"scope", "uid", "gid", "fingerprint", "positiveScanCount", *FLAGS})
    require(proof["scope"] == "actual-installed-systemd-public-file-discovery")
    for name in ("uid", "gid"):
        require(type(proof[name]) is int and proof[name] > 0)
    require(isinstance(proof["fingerprint"], str) and re.fullmatch(r"[a-f0-9]{64}", proof["fingerprint"]))
    require(type(proof["positiveScanCount"]) is int and 2 <= proof["positiveScanCount"] <= 10000)
    require(all(proof[name] is True for name in FLAGS))
    return {FIELD: copy.deepcopy(proof)}


def verify_workflow(value, workflow):
    if value.get("suite") == SUITE:
        require(workflow in (".github/workflows/certops-linux-systemd.yml", ".github/workflows/certops-linux-published-upgrade.yml"))
