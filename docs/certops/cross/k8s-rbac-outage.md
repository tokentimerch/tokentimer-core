# Kubernetes outage, watch, and RBAC

API timeout, a missed watch, and missing RBAC each fail closed. The helper does not open a socket and does not talk to a cluster. `kubernetesQualified` stays false even when a caller passes a cluster probe.

The suite level is real-host and the suite status stays pending because a live cluster is required. A missing cluster fails closed. `hostCapabilityAbsentIsPass` is false.

The catalog rows `controller.restart-watch`, `controller.rbac-boundary`, and `controller.observe` are annotated only. This file does not promote them.
