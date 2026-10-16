# Native retention reference guards and configuration boundaries

The supporting host fixture creates a fresh retention ledger for its actual
owned superseded certificate. Three additional native collector scenarios add
two explicit supporting job/rollback reference entries, close one while the
other remains active, and finally close both using production ledger APIs.
An unknown reference must not close either known reference. Fresh child
processes read the actual protected ledger after each transition.

- `windows-retention-two-open-references-protect`
- `windows-retention-one-closed-reference-still-protects`
- `windows-retention-all-closed-respects-real-deadline`

Both active-reference states must defer with `active_reference_present`.
After both close, the actual native sweep must still defer with
`deadline_not_reached`. Independent observations require unchanged exact
machine RSA CNG identity/provider/non-exportability, public certificate bytes,
immutable original cutover/expiry/store/ownership coordinates and trusted TLS
from the owned replacement. These supporting ledger references are explicit
fixture prerequisites. They do not represent an actual AD CS enrollment or
claim an installed agent completed a rollback journal operation.

The configured retention remains 24 hours and the real clock is never
substituted. Closing references must not bypass that policy. This short fixture
does not qualify elapsed 24-hour deletion, expiry cleanup, actual AD CS journal
recovery or the background sweep cadence. Its native execution remains pending.

Separate supporting filesystem tests load real production configuration at the
default, minimum 24-hour and maximum 720-hour policies, crossed with valid
positive sweep intervals. Invalid types, fractional/out-of-range hours and
nonpositive/fractional intervals fail without rewriting configuration or the
owned custody marker. Those loader checks neither run a service nor prove that
an extremely long interval has elapsed. Native reports expose only six bounded
facts, explicit supporting scope and `elapsed24HourQualified: false`.
