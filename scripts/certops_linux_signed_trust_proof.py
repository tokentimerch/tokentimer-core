"""Closed public signed Ubuntu trust projection. Manual workflow_dispatch only. Not execution evidence."""
import copy
import re
SUITE = "linux-public-signed-trust-lifecycle"
FIELD = "nativeSignedTrustLifecycle"
FLAGS = ['actualAdminAdmission', 'managerRefusedBeforeMutation', 'freshDeclaredTrustCapability', 'fourSignedCurrentClaims', 'fourConsumedNonces', 'claimBoundTrustEvidence', 'actualNativeReceiptTransitions', 'defaultOsRootLeafTrust', 'defaultOsIntermediateLeafTrust', 'intermediateRemovalRefusesDependentLeaf', 'rootReceiptAndSourcePreserved', 'rootRemovalRefusesBothLeaves', 'originalAgentRetainedDrain', 'ownedSourcesAndDerivedReferencesAbsent', 'publicAndPrivateCleanupCompleted']

def require(ok):
    if not ok:
        raise ValueError("Invalid signed native trust evidence")

def project_report(report):
    require(isinstance(report,dict) and report.get("suite")==SUITE and report.get("platform")=="linux" and report.get("architecture")=="x64")
    p=report.get(FIELD)
    require(isinstance(p,dict) and set(p)=={"scope","workspaceId","agentId","anchorIds","jobIds","claimIds","fingerprints","backgroundReconciliationQualified",*FLAGS})
    require(p["scope"]==SUITE and p["backgroundReconciliationQualified"] is False)
    uuid=lambda x: isinstance(x,str) and re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}",x)
    require(uuid(p["workspaceId"]) and uuid(p["agentId"]))
    for name,count in (("anchorIds",2),("jobIds",4),("claimIds",4),("fingerprints",2)):
        values=p[name]
        valid=(lambda x: isinstance(x,str) and re.fullmatch(r"[a-f0-9]{64}",x)) if name=="fingerprints" else uuid
        require(isinstance(values,list) and len(values)==count and all(valid(x) for x in values) and len(set(values))==count)
    require(all(p[f] is True for f in FLAGS))
    e=report.get("qualificationEnvironment")
    require(isinstance(e,dict) and e.get("osFamily")=="linux" and e.get("distribution")=="ubuntu" and e.get("osVersion")=="24.04" and e.get("measurement")=="native" and e.get("executionSurface")=="disposable-vm")
    return {FIELD:copy.deepcopy(p)}
