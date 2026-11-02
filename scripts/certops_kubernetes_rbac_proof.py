"""Closed public native startup-denial/recovery projection; never execution evidence."""
import copy
import re

FIELD = "nativeKubernetesRbacStartupRecovery"
SCOPE = "native-kubernetes-mounted-serviceaccount-rbac-startup-denial-recovery"
FLAGS = "namespaceOwnershipVerified deniedCertificateAbsent sameObserverRecovered productionWatchObserved recoveryIdempotent publicIssuedLeafVerified noClusterLevelMutation".split()


def project_report(report):
    value = report.get(FIELD)
    def require(condition):
        if not condition:
            raise ValueError("Invalid native Kubernetes RBAC startup recovery proof")
    require(report.get("suite") == "kubernetes-host")
    require(isinstance(value, dict) and set(value) == {"schemaVersion", "scope", "listStatus", "watchStatus", "createStatus", "certificateUid", "createdCertificateUid", "missedResourceVersion", "watchedResourceVersion", *FLAGS})
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["scope"] == SCOPE)
    for name in ("listStatus", "watchStatus", "createStatus"):
        require(type(value[name]) is int and value[name] == 403)
    for name in ("certificateUid", "createdCertificateUid"):
        require(isinstance(value[name], str) and re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", value[name]))
    require(value["certificateUid"] != value["createdCertificateUid"])
    for name in ("missedResourceVersion", "watchedResourceVersion"):
        require(isinstance(value[name], str) and re.fullmatch(r"[1-9][0-9]{0,19}", value[name]))
    require(int(value["watchedResourceVersion"]) > int(value["missedResourceVersion"]))
    for flag in FLAGS:
        require(value[flag] is True)
    return {FIELD: copy.deepcopy(value)}
