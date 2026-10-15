# Installed signing-pin corruption refusal

This bounded source exercises the production persisted signing-pin reader with
two present-file faults: malformed JSON and invalid required fields. The real
LocalSystem service must reach a fresh stopped/drained state with the specific
reader error for each. It must not silently start unsigned or replace its
registration identity.

The retained original pin descriptor owns every write and exact repair. The
original operator configuration, credential, installed service paths, machine
CNG certificate/key association, native binding and trusted TLS are preserved.
Only exact original-file restoration, a new actual SYSTEM child and a fresh
authenticated heartbeat permit removal of the private backup and sticky guard.
Unknown ownership or process drainage preserves the fixture.

This covers corrupt **present** pins while idle. Missing-pin registration,
signing-key rotation, in-flight certificate recovery and native execution are
not qualified. The actual reader tests use public temporary control files only;
the actual parent, bounded sidecar reporter, producer and strict Node/Python projections require its named scenario in all ten existing Windows profile/Server cells. Source fingerprints are mandatory; no native execution is claimed.
