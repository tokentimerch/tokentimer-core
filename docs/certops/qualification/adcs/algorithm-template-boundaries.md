# AD CS algorithm and template boundaries

Four mandatory native controls complement the existing incompatible-key cases:
RSA-2048 against the published RSA-3072 template, RSA-3072 against RSA-4096, and
P-256 against P-384 templates with schemas 3 and 4. They use existing owned safe
templates and require the installed LocalSystem candidate to refuse signed public
enrollments before native CA request allocation or CNG generation.

Each refusal is bound to the actual matching-template positive issuance scenario,
its native CA RequestId and public leaf fingerprint. Before and after the refusal,
the helper independently verifies that positive certificate's exact public DER,
machine CNG name and unique identity, provider, nonexportable policy and size, plus
its actively served trusted IIS TLS leaf. The helper runs before the original
positive fixtures are renewed. A fixture incapable of issuance cannot satisfy
these controls.

Actual native preflight must independently report the expected published template,
safe CA/template verdict, schema, minimum size and asymmetric algorithm. The public
issuer confirmation must succeed. The refusal must belong to an actual assigned
agent claim; its enrollment has no RequestId, its native CA subject has no request,
and its CNG key, accepted certificate, enrollment journal and custody record are
absent. Neither template mutation nor a synthetic CA outcome substitutes for this
path.

Both comprehensive root and hierarchy lab suites require the four cases and their
closed `nativeAlgorithmBoundaries` report. The dedicated pending-elapsed suite is
unchanged. These sources and pure policy/report checks are implemented; native
forest execution is pending. They do not qualify every incompatible template
combination, OCSP behavior or signed CMC renewal semantics.
