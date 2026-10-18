# Crash experiments

This is an integration contract for response-loss, journal-phase, and key-generation crash experiments.

Each proof sets `releaseQualificationSatisfied` to false. `verifyProof` requires that value. A caller that treats the report as qualified receives an error. These experiments cannot satisfy release qualification.

`nativeExecutionQualified` stays false. `hostCapabilityAbsentIsPass` stays false. A missing lab fails closed. No disposable forest is executed. The manual workflow writes a failed report and does not publish it as a release artifact.
