"""Closed public projection of native nonroot Linux backup-DAC evidence.

Schema validation cannot establish native execution. The release collector checks
trusted workflow/source/candidate identity and the committed environment separately.
No private local file snapshots, child inputs or paths are retained here.
"""
import copy

SUITE = "filesystem-linux-backup-dac-host"
FIELD = "nativeLinuxBackupDac"
SCOPE = "native-linux-nonroot-backup-dac-refusal"
FLAGS = "nonrootWithoutCapabilities actualInitialDeployment actualRotationDeployment independentWriteEacces productionBackupRefused predecessorIdentityPreserved outsideSentinelPreserved backupDirectoryRestored actualRecoveryDeployment ownedCleanupCompleted".split()
FIELDS = {"schemaVersion", "scope", "uid", "gid", *FLAGS}


def require(condition):
    if not condition:
        raise ValueError("Invalid native Linux backup-DAC proof")


def verify_proof(proof):
    require(isinstance(proof, dict) and set(proof) == FIELDS)
    require(type(proof["schemaVersion"]) is int and proof["schemaVersion"] == 1)
    require(proof["scope"] == SCOPE)
    for field in ("uid", "gid"):
        require(type(proof[field]) is int and 0 < proof[field] <= 9007199254740991)
    for field in FLAGS:
        require(proof[field] is True)
    return True


def project_report(value):
    require(isinstance(value, dict) and value.get("suite") == SUITE)
    require(value.get("platform") == "linux" and value.get("architecture") == "x64")
    environment = value.get("qualificationEnvironment")
    require(isinstance(environment, dict)
            and environment.get("osFamily") == "linux"
            and environment.get("distributionId") == "ubuntu"
            and environment.get("distributionVersion") in ("22.04", "24.04")
            and environment.get("measurement") == "native"
            and environment.get("executionSurface") == "disposable-vm")
    proof = value.get(FIELD)
    verify_proof(proof)
    return {FIELD: copy.deepcopy(proof)}
