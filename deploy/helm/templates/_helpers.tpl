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
{{- define "tokentimer.cnpgPassword" -}}
{{- $secretName := printf "%s-pg-secret" (include "tokentimer.fullname" .) -}}
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
