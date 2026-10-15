# Installed Windows credential startup refusals

An already registered agent reads and validates its protected local credential before registering or polling for certificate jobs. An empty file and a malformed credential must fail explicitly, rather than silently creating a replacement identity. These source variants retain the actual original credential privately and select the exact production reader errors; public evidence contains no credential bytes.

The native composition uses the existing retained-file startup engine, with its exact stopped LocalSystem service, private original-file ownership guard, fresh failed-child drainage, unchanged server identity/jobs/configuration/signing pin and protected CNG/native binding/trusted TLS. Exact credential restoration and a repaired authenticated SYSTEM child must precede guard release. No missing-file registration, bootstrap replacement or in-flight certificate operation is implied.

Supporting tests exercise the actual protected credential reader on owned public control files and verify exact repair. Native engine, parent lifecycle and mandatory strict report checks are wired across all five key profiles on both Server versions. Native Windows execution remains pending. This is a bounded startup recovery case, not a claim that all credential loss or compromise scenarios recover automatically.
