{{/*
Expand the name of the chart.
*/}}
{{- define "tokentimer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name (truncated to 63 chars for K8s label limits).
*/}}
{{- define "tokentimer.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart name and version for the chart label.
*/}}
{{- define "tokentimer.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to every resource.
*/}}
{{- define "tokentimer.labels" -}}
helm.sh/chart: {{ include "tokentimer.chart" . }}
{{ include "tokentimer.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels (immutable after creation).
*/}}
{{- define "tokentimer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tokentimer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name.
*/}}
{{- define "tokentimer.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "tokentimer.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Build a container image reference.
Usage: {{ include "tokentimer.image" (dict "image" .Values.api.image "global" .Values.global "defaultTag" .Chart.AppVersion) }}
Supports: per-component registry override, global registry, digest pinning.
*/}}
{{- define "tokentimer.image" -}}
{{- $registry := .image.registry | default .global.imageRegistry -}}
{{- if .image.digest -}}
  {{- if $registry -}}{{ $registry }}/{{- end -}}{{ .image.repository }}@{{ .image.digest }}
{{- else -}}
  {{- if $registry -}}{{ $registry }}/{{- end -}}{{ .image.repository }}:{{ .image.tag | default .defaultTag }}
{{- end -}}
{{- end -}}

{{/*
Name of the main application secret (chart-generated or user-provided).
*/}}
{{- define "tokentimer.secretName" -}}
{{- .Values.config.existingSecret | default (printf "%s-secrets" (include "tokentimer.fullname" .)) }}
{{- end }}

{{/*
Safely read a key from an existing secret's base64-encoded data map.
Returns the decoded value if the key exists, otherwise the provided fallback.
Usage: include "tokentimer.secretLookup" (dict "data" $existingData "key" "MY_KEY" "fallback" "defaultval")
*/}}
{{- define "tokentimer.secretLookup" -}}
{{- if and .data (hasKey .data .key) -}}
  {{- index .data .key | b64dec -}}
{{- else -}}
  {{- .fallback -}}
{{- end -}}
{{- end -}}

{{/*
Generate (or reuse) the CloudNativePG bootstrap password.
The value is cached on .Values so both the CNPG Cluster secret and the app
secret receive the same password within a single render pass.
On upgrades, the existing secret is read via `lookup` to avoid regenerating.
*/}}
{{- define "tokentimer.pgSecretName" -}}
{{- if .Values.postgresql.auth.existingSecret -}}
{{- .Values.postgresql.auth.existingSecret -}}
{{- else -}}
{{- printf "%s-pg-secret" (include "tokentimer.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "tokentimer.cnpgPassword" -}}
{{- $secretName := include "tokentimer.pgSecretName" . -}}
{{- $existingSecret := lookup "v1" "Secret" .Release.Namespace $secretName -}}
{{- if and $existingSecret $existingSecret.data (index $existingSecret.data "password") -}}
  {{- index $existingSecret.data "password" | b64dec -}}
{{- else if .Values.postgresql.auth.password -}}
  {{- .Values.postgresql.auth.password -}}
{{- else -}}
  {{- $cacheKey := "_cnpgGeneratedPassword" -}}
  {{- if not (hasKey .Values $cacheKey) -}}
    {{- $_ := set .Values $cacheKey (randAlphaNum 32) -}}
  {{- end -}}
  {{- index .Values $cacheKey -}}
{{- end -}}
{{- end -}}

{{/* ---- Database helpers ---- */}}

{{/*
Database host. CloudNativePG exposes <cluster>-rw as the read-write service.
*/}}
{{- define "tokentimer.databaseHost" -}}
{{- if .Values.postgresql.cloudnative.enabled }}
{{- printf "%s-pg-rw" (include "tokentimer.fullname" .) }}
{{- else }}
{{- required "postgresql.external.host is required when cloudnative is disabled" .Values.postgresql.external.host }}
{{- end }}
{{- end }}

{{- define "tokentimer.databasePort" -}}
{{- if .Values.postgresql.cloudnative.enabled }}5432{{- else }}{{ .Values.postgresql.external.port | default 5432 }}{{- end }}
{{- end }}

{{- define "tokentimer.databaseName" -}}
{{- if .Values.postgresql.cloudnative.enabled }}{{ .Values.postgresql.auth.database }}{{- else }}{{ .Values.postgresql.external.database }}{{- end }}
{{- end }}

{{- define "tokentimer.databaseUser" -}}
{{- if .Values.postgresql.cloudnative.enabled }}{{ .Values.postgresql.auth.username }}{{- else }}{{ .Values.postgresql.external.username }}{{- end }}
{{- end }}

{{/* ---- ConfigMap / Secret checksums (rollout on helm upgrade) ---- */}}

{{/*
Rendered ConfigMap data keys only (stable input for checksum/config).
*/}}
{{- define "tokentimer.configmapData" -}}
NODE_ENV: {{ .Values.config.nodeEnv | default "production" | quote }}
APP_URL: {{ .Values.config.baseUrl | quote }}
API_URL: {{ .Values.config.apiUrl | quote }}
TRUST_PROXY_HOPS: {{ .Values.config.trustProxyHops | default 2 | quote }}
{{- if or .Values.postgresql.cloudnative.enabled (not .Values.postgresql.external.existingSecret) }}
DB_HOST: {{ include "tokentimer.databaseHost" . | quote }}
DB_PORT: {{ include "tokentimer.databasePort" . | quote }}
DB_NAME: {{ include "tokentimer.databaseName" . | quote }}
DB_USER: {{ include "tokentimer.databaseUser" . | quote }}
{{- if .Values.postgresql.cloudnative.enabled }}
DB_SSL: "require"
{{- else if and .Values.postgresql.external.enabled .Values.postgresql.external.sslMode }}
DB_SSL: {{ .Values.postgresql.external.sslMode | quote }}
{{- end }}
{{- end }}
{{- if .Values.config.alertThresholds }}
ALERT_THRESHOLDS: {{ .Values.config.alertThresholds | quote }}
{{- end }}
{{- if not .Values.config.existingSecret }}
{{- if not .Values.config.disableAdminBootstrap }}
ADMIN_EMAIL: {{ .Values.config.adminEmail | required "config.adminEmail is required for initial admin setup (or set config.disableAdminBootstrap=true / config.existingSecret)" | quote }}
{{- end }}
ADMIN_NAME: {{ .Values.config.adminName | default "Administrator" | quote }}
{{- end }}
{{- if .Values.config.disableAdminBootstrap }}
DISABLE_ADMIN_BOOTSTRAP: "true"
{{- end }}
{{- if .Values.monitoring.metrics.enabled }}
ENABLE_METRICS: "true"
{{- end }}
{{- if .Values.monitoring.metrics.pushgatewayUrl }}
PUSHGATEWAY_URL: {{ .Values.monitoring.metrics.pushgatewayUrl | quote }}
{{- end }}
{{- if not .Values.smtp.existingSecret }}
{{- if .Values.smtp.host }}
SMTP_HOST: {{ .Values.smtp.host | quote }}
{{- end }}
{{- if .Values.smtp.port }}
SMTP_PORT: {{ .Values.smtp.port | quote }}
{{- end }}
{{- if .Values.smtp.user }}
SMTP_USER: {{ .Values.smtp.user | quote }}
{{- end }}
{{- if .Values.smtp.fromEmail }}
FROM_EMAIL: {{ .Values.smtp.fromEmail | quote }}
{{- end }}
{{- if .Values.smtp.fromName }}
FROM_EMAIL_NAME: {{ .Values.smtp.fromName | quote }}
{{- end }}
{{- if .Values.smtp.secure }}
SMTP_SECURE: {{ .Values.smtp.secure | quote }}
{{- end }}
{{- if .Values.smtp.requireTls }}
SMTP_REQUIRE_TLS: {{ .Values.smtp.requireTls | quote }}
{{- end }}
{{- end }}
{{- if not .Values.twilio.existingSecret }}
{{- if .Values.twilio.accountSid }}
TWILIO_ACCOUNT_SID: {{ .Values.twilio.accountSid | quote }}
{{- end }}
{{- if .Values.twilio.whatsappFrom }}
TWILIO_WHATSAPP_FROM: {{ .Values.twilio.whatsappFrom | quote }}
{{- end }}
{{- if .Values.twilio.testContentSid }}
TWILIO_WHATSAPP_TEST_CONTENT_SID: {{ .Values.twilio.testContentSid | quote }}
{{- end }}
{{- if .Values.twilio.alertContentSidExpires }}
TWILIO_WHATSAPP_ALERT_CONTENT_SID_EXPIRES: {{ .Values.twilio.alertContentSidExpires | quote }}
{{- end }}
{{- if .Values.twilio.alertContentSidExpired }}
TWILIO_WHATSAPP_ALERT_CONTENT_SID_EXPIRED: {{ .Values.twilio.alertContentSidExpired | quote }}
{{- end }}
{{- if .Values.twilio.alertContentSidEndpointDown }}
TWILIO_WHATSAPP_ALERT_CONTENT_SID_ENDPOINT_DOWN: {{ .Values.twilio.alertContentSidEndpointDown | quote }}
{{- end }}
{{- if .Values.twilio.alertContentSidEndpointRecovered }}
TWILIO_WHATSAPP_ALERT_CONTENT_SID_ENDPOINT_RECOVERED: {{ .Values.twilio.alertContentSidEndpointRecovered | quote }}
{{- end }}
{{- if .Values.twilio.weeklyDigestContentSid }}
TWILIO_WHATSAPP_WEEKLY_DIGEST_CONTENT_SID: {{ .Values.twilio.weeklyDigestContentSid | quote }}
{{- end }}
{{- end }}
{{- end -}}

{{- define "tokentimer.configmapChecksum" -}}
{{- include "tokentimer.configmapData" . | sha256sum }}
{{- end -}}

{{/*
Stable secret inputs (avoids randAlphaNum in checksum/secret during helm template).
*/}}
{{- define "tokentimer.secretChecksum" -}}
{{- dict
  "sessionSecret" (.Values.config.sessionSecret | default "")
  "adminPassword" (.Values.config.adminPassword | default "")
  "pgPassword" (.Values.postgresql.auth.password | default "")
  "externalPgPassword" (.Values.postgresql.external.password | default "")
  "smtpPassword" (.Values.smtp.password | default "")
  "twilioAuthToken" (.Values.twilio.authToken | default "")
  "existingSecret" (.Values.config.existingSecret | default "")
  "pgExistingSecret" (.Values.postgresql.auth.existingSecret | default "")
  "externalPgExistingSecret" (.Values.postgresql.external.existingSecret | default "")
  "smtpExistingSecret" (.Values.smtp.existingSecret | default "")
  "twilioExistingSecret" (.Values.twilio.existingSecret | default "")
  "adminEmail" (.Values.config.adminEmail | default "")
  "disableAdminBootstrap" .Values.config.disableAdminBootstrap
  | toYaml | sha256sum }}
{{- end -}}

{{/*
Pod annotations that trigger a rolling restart when Helm values or release revision change.
checksum/helm-release-revision covers parent-chart-only resources (e.g. enterprise SSO ConfigMap).
*/}}
{{- define "tokentimer.apiRolloutPodAnnotations" -}}
checksum/config: {{ include "tokentimer.configmapChecksum" . }}
checksum/secret: {{ include "tokentimer.secretChecksum" . }}
checksum/helm-release-revision: {{ .Release.Revision | quote }}
{{- with .Values.api.envFrom }}
checksum/api-envfrom: {{ . | toYaml | sha256sum }}
{{- end }}
{{- end -}}

{{- define "tokentimer.dashboardRolloutPodAnnotations" -}}
checksum/config: {{ include "tokentimer.configmapChecksum" . }}
checksum/dashboard-env: {{ .Values.dashboard.env | toYaml | sha256sum }}
checksum/helm-release-revision: {{ .Release.Revision | quote }}
{{- end -}}

{{- define "tokentimer.workerRolloutPodAnnotations" -}}
checksum/config: {{ include "tokentimer.configmapChecksum" . }}
checksum/secret: {{ include "tokentimer.secretChecksum" . }}
checksum/helm-release-revision: {{ .Release.Revision | quote }}
{{- with .Values.worker.envFrom }}
checksum/worker-envfrom: {{ . | toYaml | sha256sum }}
{{- end }}
{{- end -}}

{{/* ---- Shared pod snippets ---- */}}

{{/*
envFrom block shared by all workloads. Mounts the configmap, the main secret,
and any existing secrets for DB / SMTP / Twilio.
*/}}
{{- define "tokentimer.envFrom" -}}
- configMapRef:
    name: {{ include "tokentimer.fullname" . }}-config
- secretRef:
    name: {{ include "tokentimer.secretName" . }}
{{- if .Values.postgresql.external.existingSecret }}
- secretRef:
    name: {{ .Values.postgresql.external.existingSecret }}
{{- end }}
{{- if .Values.smtp.existingSecret }}
- secretRef:
    name: {{ .Values.smtp.existingSecret }}
{{- end }}
{{- if .Values.twilio.existingSecret }}
- secretRef:
    name: {{ .Values.twilio.existingSecret }}
{{- end }}
{{- end }}

{{/*
Additional envFrom entries from values (api.envFrom / worker.envFrom).
configMapRef.name and secretRef.name may use Helm tpl, e.g. '{{ .Release.Name }}-overlay-env'.
*/}}
{{- define "tokentimer.renderEnvFromExtras" -}}
{{- $root := .root }}
{{- range .entries }}
{{- if .configMapRef }}
- configMapRef:
    name: {{ tpl (.configMapRef.name | toString) $root | quote }}
{{- end }}
{{- if .secretRef }}
- secretRef:
    name: {{ tpl (.secretRef.name | toString) $root | quote }}
    {{- if hasKey .secretRef "optional" }}
    optional: {{ .secretRef.optional }}
    {{- end }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Extra pod volumes from values (api.extraVolumes / worker.extraVolumes).
secret.secretName and configMap.name may use Helm tpl.
*/}}
{{- define "tokentimer.renderExtraVolumes" -}}
{{- $root := .root }}
{{- range .volumes }}
- name: {{ .name }}
  {{- if .emptyDir }}
  emptyDir: {}
  {{- else if .secret }}
  secret:
    secretName: {{ tpl (.secret.secretName | toString) $root | quote }}
    {{- if hasKey .secret "optional" }}
    optional: {{ .secret.optional }}
    {{- end }}
  {{- else if .configMap }}
  configMap:
    name: {{ tpl (.configMap.name | toString) $root | quote }}
    {{- if hasKey .configMap "optional" }}
    optional: {{ .configMap.optional }}
    {{- end }}
  {{- else }}
  {{- omit . "name" | toYaml | nindent 2 }}
  {{- end }}
{{- end }}
{{- end }}
