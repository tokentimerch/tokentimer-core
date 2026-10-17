# Linux installation, reboot, and upgrade

Reboot is not claimed. `realRebootQualified` stays false. Upgrade rollback writes the next unit only inside the owned root, then restores the previous unit bytes. An in-use key file passed to the same call is left unchanged.

A missing systemd host fails closed before a unit file is created. `hostCapabilityAbsentIsPass` is false. The local proof level is host-integration. The suite level is integration and does not qualify a host reboot.

The catalog rows `linux-install.systemd-registration`, `linux-install.restart-recovery`, `linux-install.uninstall`, `deploy.os-service`, and `deploy.no-systemd` are annotated only. This file does not promote them.
