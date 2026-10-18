# Uncertain state abandonment

This is an integration contract for a successful abandonment. Abandonment is accepted only when the state is `submission_uncertain`, no in-use key is deleted, and no foreign request is touched.

A successful abandon still leaves `nativeExecutionQualified` false. `hostCapabilityAbsentIsPass` stays false. A missing lab fails closed.

The forest journey remains in `tests/e2e/helpers/certops-adcs-uncertain-abandon.js`. This local contract does not replace that journey and does not claim a disposable forest ran.
