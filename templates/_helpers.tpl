{{/*
Expand the name of the chart.
*/}}
{{- define "acm-certificate-agent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "acm-certificate-agent.fullname" -}}
{{- $chartName := include "acm-certificate-agent.name" . }}
{{- default $chartName .Values.fullNameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "acm-certificate-agent.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "acm-certificate-agent.labels" -}}
helm.sh/chart: {{ include "acm-certificate-agent.chart" . }}
{{ include "acm-certificate-agent.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- if .Values.context.domainUsername }}
app.kubernetes.io/created-by: {{ .Values.context.domainUsername | trunc 63 | quote }}
{{- end }}
{{- if .Values.context.correlationId }}
tron/correlationId: {{ .Values.context.correlationId | trunc 63 | quote }}
{{- else }}
{{- $correlationId := include "acm-certificate-agent.fullname" . | b64enc | replace "=" "" | trunc 63 | quote }}
tron/correlationId: {{ $correlationId }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "acm-certificate-agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "acm-certificate-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
