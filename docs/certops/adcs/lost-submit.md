# Lost submit response

This is an integration contract for deterministic lost-submit reconciliation.

Zero candidate requests are a clean miss. The parser does not invent a request id. Two or more candidates are ambiguous and fail closed with no chosen request. Exactly one owned candidate may be reconciled only as a local parser result.

`nativeExecutionQualified` stays false. `hostCapabilityAbsentIsPass` stays false. A missing lab fails closed. No disposable forest is executed.
