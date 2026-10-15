"""Closed public projection for actual same-process paired filesystem rotations.

Only public fingerprints, native lineage and mandatory boolean observations
survive. This schema does not establish execution or cross-process locking.
"""
import copy
import re

SUITE = "filesystem-host"
FIELD = "nativeFilesystemConcurrency"
SCOPE = "native-filesystem-same-process-paired-rotation"
FLAGS = "actualBaselineDeployed bothSubmittedBeforeAwait bothNativeMutationsCompleted finalPairAndChainVerified serialBackupLineageVerified privateKeyPermissionsVerified privateStagingPreserved outsideSentinelUnchanged trustedBaselineAndFinalTlsVerified nativeListenerClosed ownedCleanupCompleted".split()
FIELDS = {"schemaVersion", "scope", "processScope", "contenderCount", "completedMutations", "backupNamespaces", "fingerprints", "spkiFingerprints", "completionOrder", "backupPredecessors", "servedBeforeFingerprint", "servedAfterFingerprint", *FLAGS}
RETENTION_FIELD = "nativeFilesystemBackupRetention"
RETENTION_FLAGS = ["twoActualInitialDeployments","twoActualIndependentRotations","sameBasenamesAndBackupDirectory","olderOwnedGenerationPruned","currentRollbackGenerationPreserved","otherDestinationBackupsPreserved","legacyAndOperatorFilesPreserved","outsideSentinelPreserved","threePredecessorPairsVerified","finalCertificateKeyAndChainVerified","nativePrivateKeyPermissionsVerified","privateStagingPreserved","ownedCleanupCompleted"]

def verify_retention(value):
    require(isinstance(value, dict) and set(value) == {"schemaVersion", "scope", "retentionCount", "targetCount", "actualRotations", "fingerprints", *RETENTION_FLAGS})
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1)
    require(value["scope"] == "native-filesystem-bounded-backup-retention-destination-isolation")
    for key, expected in (("retentionCount", 1), ("targetCount", 2), ("actualRotations", 4)):
        require(type(value[key]) is int and value[key] == expected)
    rows = value["fingerprints"]
    require(isinstance(rows, list) and len(rows) == 3 and all(isinstance(row, str) and re.fullmatch(r"[a-f0-9]{64}", row) for row in rows) and len(set(rows)) == 3)
    for flag in RETENTION_FLAGS:
        require(value[flag] is True)

ALIAS_FIELD = "nativeFilesystemBackupAlias"
ALIAS_FLAGS = "actualInitialPairAndChain actualNativeDirectoryAlias lexicalAliasAllowed canonicalOutsideRefused productionRealpathPolicyRefusal predecessorBytesAndIdentityPreserved noOutsideBackupCreated sourceKeyPreserved actualAllowedDirectoryRecovery threePredecessorBackupsVerified privateKeyPermissionsVerified ownedCleanupCompleted".split()


def verify_alias(value, platform):
    require(isinstance(value, dict) and set(value) == {"schemaVersion", "scope", "aliasKind", "refusalStage", "fingerprints", *ALIAS_FLAGS})
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1)
    require(value["scope"] == "native-filesystem-explicit-backup-directory-alias-refusal")
    require(value["aliasKind"] == ("junction" if platform == "win32" else "symlink"))
    require(value["refusalStage"] == "realpath-policy")
    rows = value["fingerprints"]
    require(isinstance(rows, list) and len(rows) == 2 and all(isinstance(row, str) and re.fullmatch(r"[a-f0-9]{64}", row) for row in rows) and len(set(rows)) == 2)
    for flag in ALIAS_FLAGS:
        require(value[flag] is True)


def require(condition):
    if not condition:
        raise ValueError("Invalid native paired-filesystem concurrency proof")


def verify_proof(value):
    require(isinstance(value, dict) and set(value) == FIELDS)
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1)
    require(value["scope"] == SCOPE and value["processScope"] == "one-native-node-process")
    require(type(value["contenderCount"]) is int and value["contenderCount"] == 2)
    require(type(value["completedMutations"]) is int and value["completedMutations"] == 2)
    require(value["backupNamespaces"] == "default-alongside-target")
    for field in FLAGS:
        require(value[field] is True)
    for field in ("fingerprints", "spkiFingerprints"):
        rows = value[field]
        require(isinstance(rows, list) and len(rows) == 3
                and all(isinstance(row, str) and re.fullmatch(r"[a-f0-9]{64}", row) for row in rows)
                and len(set(rows)) == 3)
    require(value["completionOrder"] == ["contender-b", "contender-c"])
    require(value["backupPredecessors"] == value["fingerprints"][:2])
    require(value["servedBeforeFingerprint"] == value["fingerprints"][0])
    require(value["servedAfterFingerprint"] == value["fingerprints"][2])
    return True


def project_report(value):
    require(isinstance(value, dict) and value.get("suite") == SUITE)
    require(value.get("architecture") == "x64")
    environment = value.get("qualificationEnvironment")
    require(isinstance(environment, dict) and environment.get("measurement") == "native")
    if value.get("platform") == "linux":
        require(environment.get("osFamily") == "linux"
                and environment.get("distributionId") == "ubuntu"
                and environment.get("distributionVersion") in ("22.04", "24.04")
                and environment.get("executionSurface") == "host")
    elif value.get("platform") == "win32":
        require(environment.get("osFamily") == "windows"
                and environment.get("osVersion") in ("2022", "2025")
                and type(environment.get("productType")) is int
                and environment["productType"] in (2, 3))
    else:
        require(False)
    verify_proof(value.get(FIELD))
    verify_alias(value.get(ALIAS_FIELD), value.get("platform"))
    verify_retention(value.get(RETENTION_FIELD))
    return {FIELD: copy.deepcopy(value[FIELD]), ALIAS_FIELD: copy.deepcopy(value[ALIAS_FIELD]), RETENTION_FIELD: copy.deepcopy(value[RETENTION_FIELD])}
