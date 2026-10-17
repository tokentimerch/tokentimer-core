# Issuer adoption and capacity

The native forest journey remains the `native-adcs-issuer-reassignment` suite. This contract is the remainder: a sixth reservation at the shared cap fails closed without evicting a slot, and adoption of an issuer that is not in the owned set fails. `nativeCell` stays `pending`. Nothing here marks that cell qualified.

A missing forest fails closed. `hostCapabilityAbsentIsPass` is false.

The catalog rows `renewal.ca-capacity` and `renewal.issuer-switch` are annotated only. This file does not promote them.
