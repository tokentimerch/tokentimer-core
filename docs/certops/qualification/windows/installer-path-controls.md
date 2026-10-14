# Installer copy paths and reparse boundaries

The production Windows package copy preflights the candidate, existing staging
tree and their ancestors before creating any destination entry. A linked
source root, nested source directory, source ancestor, destination root, nested
destination directory or destination ancestor is refused. Source `node_modules`
and `.git` directories remain excluded; even their junctions are neither
followed nor copied. This protects the copy phase before activation's separate
reparse guards can run. The preflight does not claim atomic protection against
a privileged actor concurrently replacing paths after validation.

The supporting `certops-installer-path-support.js` command executes the actual
production copy/activation functions extracted from the candidate AST. Three
positive controls use spaces, Unicode and literal brackets in candidate/root
and leaf names, verify actual activation, and preserve predecessor bytes and
native directory/file identity. Six copy junction controls require refusal
without outside writes; source refusals must not create staging at all. Four
activation controls refuse linked app/staging/previous/parent directories.
Every “outside” target remains inside the exclusively owned temporary fixture.

Independent native file IDs and SHA-256 hashes protect outside and predecessor
markers. Junctions are removed individually before exact owned-root cleanup.
The wrapper accepts only successful command exit and all bounded proof facts,
including actual temporary-fixture absence. Pure tests never execute native
operations. These controls do not run installer top-level, service, registry,
certificate or CNG operations and cannot qualify installed-service paths.

Missing/truncated/wrong-architecture service-host pre-activation refusal is a
separate product gap: the installer currently checks host existence after
activation and does not perform its own pre-activation PE validation. Existing
archive PE/digest tests must not be presented as that missing installer check.
