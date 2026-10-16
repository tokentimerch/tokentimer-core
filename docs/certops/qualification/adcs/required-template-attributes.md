# Required native template attributes

Two source cases extend the live template safety checks with predicates that
previously had only pure parser coverage: zero `msPKI-Minimal-Key-Size` and an
absent `msPKI-Certificate-Name-Flag`. An absent minimum-key attribute is already
covered separately. These are unreadable required descriptors, not new supported
template forms. Both cases are mandatory in the root and hierarchy release suites. Native execution remains pending.

Each case first obtains a genuine known-safe native descriptor for the owned
`TTQualificationRSAShort` template. Parent-visible restoration ownership is
registered before LDAP mutation. Native preflight must report `unreadable` and
`template_unreadable`, including the exact zero/null observation. Public
confirmation must be refused. A real signed request through the already
confirmed issuer must report `ADCS_TEMPLATE_UNSAFE` before any CA request or
machine CNG allocation. The installed serving certificate, native key
association, binding, authenticated TLS, configuration and registered credential
must remain unchanged.

Exact original public LDAP attributes must be restored before a fresh genuine
native preflight proves the original safe descriptor again. An unresolved
restoration receipt blocks parent native, public and state cleanup. Failures
preserve recovery evidence for independently owned disposable-lab teardown.

The isolated native preflight cohorts handle six additional genuine checks
(safe, mutated and restored for each case), without raising the primary
workspace limit. Wrong-typed algorithm strings are outside this scope until
actual directory storage and native rendering are established. Pure parser and
proof checks cannot establish native LDAP restoration or release qualification.
