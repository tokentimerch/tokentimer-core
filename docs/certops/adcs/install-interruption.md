# Installation phase interruption

This is an integration contract for recovery across the remaining installation phases: role install, CA config, template publish, ACL grant, and the IIS enroll site.

Each phase restarts the same owned target. An in-use key is never deleted. A blanket netsh reset is refused. Power-loss durability stays false. A real reboot stays false. `nativeExecutionQualified` stays false. `hostCapabilityAbsentIsPass` stays false.

A missing lab fails closed. No disposable forest is executed. The manual workflow writes a failed report and does not publish it as a release artifact.
