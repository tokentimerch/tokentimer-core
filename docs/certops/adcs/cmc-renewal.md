# Signed CMC renewal

This is an integration contract for CMC renewal semantics. An owned renewal must carry a signature. Unsigned CMC fails. Foreign CMC fails.

Repeated unattended renewal is a separate case. The second renewal uses the same template and must not reuse a consumed request id.

Both results keep `nativeExecutionQualified` false. `hostCapabilityAbsentIsPass` stays false. A missing lab fails closed. No disposable forest is executed.
