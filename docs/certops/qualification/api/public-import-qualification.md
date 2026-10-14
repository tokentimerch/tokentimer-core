# Public certificate import and private container refusal

`tests/e2e/certops-public-import-e2e.test.js` runs twelve mandatory supporting scenarios against an authenticated disposable API and PostgreSQL stack. It verifies public PEM identity facts against OpenSSL and Node's independent X509 parser, repeated and concurrent identity conservation, PEM bundles, malformed/oversized input, source-reference restrictions and private material refusal. Exact DER parsing is explicitly classified as supporting unit evidence rather than a binary HTTP upload.

The private-container scenarios generate genuine PKCS#8 DER, password-encrypted PKCS#8 DER and PKCS#12/PFX with OpenSSL. Independent public SPKI comparison proves each container actually contains the fixture certificate's private key. This includes exporting the key from the PFX locally; the extracted file and password remain in the owned temporary directory.

Requests hide these containers under an otherwise valid public certificate's nested metadata. Every request must return `422 PRIVATE_KEY_MATERIAL_REJECTED`, omit private container bytes and passwords from its response and persisted workspace audit metadata, and preserve a digest of every inventory certificate, token and identity row. Matching row counts alone cannot establish that existing metadata stayed unchanged.

Additional requests exercise base64url and hex PEM, compressed DER, nested compression and metadata deeper than the bounded material scanner accepts. These use small, owned payloads; nested or ambiguous material must fail closed without allocating a decompression bomb or creating inventory. Existing cases also reject direct PEM keys, base64 keys and a compressed nested key.

The standard API qualification runner executes the suite as `public-import-api`. `CERTOPS_PUBLIC_IMPORT_REPORT` chooses its strict report path. All twelve scenarios and the current harness digest are required. The fixture cleanup removes its own workspaces, users and temporary certificate, private key, container and password files.

Focused local execution passed all twelve scenarios with no skips. The PFX case qualifies server-side rejection of real private containers, including a common Windows interchange format. It does not import a key into the Windows Certificate Store, prove CNG custody, exercise a native CA or establish release qualification. Installed Windows and AD CS workflows supply those separate native oracles.
