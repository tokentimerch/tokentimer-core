# Windows installer first-rename refusal

The `windows-installer-first-rename-refusal` suite runs only in the RSA2048 installed-agent journey on Windows Server 2022 and 2025. Its three mandatory scenarios establish an owned native directory handle without delete sharing, execute the genuine candidate installer, and release the handle with verified child termination.

The installer must refuse its first directory rename and remove only its exact staged package. Independent observations require unchanged installed file hashes, configuration and credential bytes, the same running service PID, a strictly newer authenticated heartbeat sampled after refusal, and the original trusted IIS TLS certificate. Missing handle ownership, a successful rename, incomplete staging cleanup or absent preservation facts fail qualification.

The release collector retains only the twelve bounded proof booleans and requires current fingerprints for the helper, native handle child, installer, supporting owned-temp regression and enclosing installed journey. Both server environments are separate mandatory release slots; other key profiles cannot substitute for them.

The supporting PowerShell regression executes the extracted production activation function against disposable temporary directories. It proves actual held-handle refusal and subsequent activation after release without installing a service or modifying certificates. The full installed-service scenarios remain unexecuted until their hosted Windows workflows run. This suite makes no claim about restoration after a second-rename failure, an unchanged default installation root, or upgrading an incomplete published package.
