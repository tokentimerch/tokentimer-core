"""Narrow native service-stop projection; never qualifies other interruption stages."""
import certops_windows_stop_offline_proof as parent


def fields(report):
    proof = report.get("nativeInstalledInterruption")
    fixed = dict(scope="service-stop-during-dns-after-native-cng-journal",
                 interruptionMode="service-stop", observedStage="dns-post-after-native-cng-journal",
                 parentSuite="windows-installed-stop-offline-renewal")
    false = ("realRebootQualified", "powerLossDurabilityQualified", "originalOperationAutomaticallyRecovered")
    if (not isinstance(proof, dict) or set(proof) != {*fixed, *false, "nativeExecutionQualified", "nativeStoppedOffline"}
            or any(proof.get(key) != value for key, value in fixed.items())
            or proof.get("nativeExecutionQualified") is not True
            or any(proof.get(key) is not False for key in false)):
        raise ValueError("Actual narrow native interruption proof required")
    nested = parent.fields({**report, "nativeWindowsStoppedOffline": proof["nativeStoppedOffline"]})
    if nested != proof["nativeStoppedOffline"]:
        raise ValueError("Unrecognized native stopped/offline facts")
    return {**proof, "nativeStoppedOffline": nested}
