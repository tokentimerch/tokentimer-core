# Readable credential with an untrusted ACL

This supporting host source creates only a public synthetic credential, with no
API authority, inside a fresh owned private directory. The production reader
must initially accept it. A contained native holder pins its original file ID
without delete sharing, captures its protected DACL and adds exactly one
explicit Everyone ReadData ACE. Separate native ACL observation and an actual
successful file read prove the file is readable; the production credential
reader must nevertheless refuse the untrusted principal.

The holder restores the original DACL through the retained handle. Exact file
identity, bytes and native DACL, successful production-reader recovery, natural
holder exit and complete retained Job drainage precede removal of the public
control files. Lost receipts, altered files or uncertain restoration keep both
the durable guard and in-memory cleanup refusal. No real credential is exposed.

The source does not start an installed service or touch a certificate, machine
key, CA or Azure resource. It does not demonstrate a separate unprivileged
process reading a credential, every weak-ACL permutation or installed startup.
Native execution remains pending; supporting pure checks are not native passes.
The actual Windows host parent and strict Node/Python projections require the named case and closed proof on both Server host cells. Current causal source fingerprints are mandatory. Supporting pure and managed-policy checks do not qualify native execution.
