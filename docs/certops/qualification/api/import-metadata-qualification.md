# Certificate import metadata preservation

The `import-metadata-api` suite requires five named scenarios against an explicitly disposable API/PostgreSQL fixture and OpenSSL. It creates a genuine public certificate, imports it through the public API, then edits its token contacts and two group assignments through the authenticated token API.

Repeated and four concurrent reimports from distinct source references must preserve the original certificate/token identity, original provenance, operator name, contacts, description and group memberships. An unconfigured group combined with a contact edit must fail atomically. Independent SQL reads check persistence; cleanup removes only fixture-owned resources.

Contact-group configuration is an explicit database prerequisite. The suite does not claim mail delivery, external integration observers or native host concurrency. Its supporting integration evidence is separate from native and edition qualification.

The central API qualification runner executes the suite and its mandatory report verifier. Focused local execution passed all five scenarios with independent report verification; hosted execution remains pending.
