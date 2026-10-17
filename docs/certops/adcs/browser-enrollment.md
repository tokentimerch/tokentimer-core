# Browser preflight, confirmation, and enrollment

This is an integration contract for the browser journey. The recorded order is preflight, then confirmation, then enrollment. Confirmation is required before submit.

The contract does not launch a browser. A missing browser fails closed. `nativeExecutionQualified` stays false. `hostCapabilityAbsentIsPass` stays false. A missing lab fails closed.

No disposable forest is executed. A failed report from the manual workflow is not native qualification and is not a release artifact.

The manual workflow is `workflow_dispatch` only.

The comprehensive Server 2022/en-US root-domain run separately exports `enterprise-adcs-browser-enrollment.json` after its actual browser journey and parent cleanup succeed. That native report covers renewal of existing inventory; the local CLI contract above remains nonqualifying.
