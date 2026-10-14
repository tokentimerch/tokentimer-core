# Native Kubernetes public Secret fallback

The mandatory `controller-secret-fallback` scenario runs a candidate production-image pod with mounted in-cluster credentials. Its service account can only get three exact Secret names in its run-owned namespace. The real cert-manager TLS Secret contains its locally owned key; the production raw Secret reader returns only encoded public `tls.crt`. The production fallback parser must enrich an incomplete public observation with the independently expected leaf fingerprint and validity, without key fields or private material in its output.

The same pod requires native Kubernetes 403 on a foreign namespace, refuses a genuine malformed public Secret, refuses a real 70 KiB decoded public field and cannot read an unallowlisted Secret. Secret mutation, certificate mutation and list permissions are not granted. Only a bounded passed/failed sentinel leaves the pod; Secret bytes, service-account credentials and raw errors are never logged.

Source syntax, lint and mandatory suite/matrix guards passed. Native cluster execution remains pending. This supporting host case does not prove full API observation publication, external cert-manager issuers or every fallback policy combination.
