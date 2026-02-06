{{/*
Expand the name of the chart.
*/}}
{{- define "nklave.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "nklave.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "nklave.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "nklave.labels" -}}
helm.sh/chart: {{ include "nklave.chart" . }}
{{ include "nklave.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "nklave.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nklave.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "nklave.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "nklave.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Return the proper image name
*/}}
{{- define "nklave.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end }}

{{/*
Create the name of the configmap
*/}}
{{- define "nklave.configMapName" -}}
{{- printf "%s-config" (include "nklave.fullname" .) -}}
{{- end }}

{{/*
Create the name of the secret
*/}}
{{- define "nklave.secretName" -}}
{{- printf "%s-secret" (include "nklave.fullname" .) -}}
{{- end }}

{{/*
Create the name of the PVC
*/}}
{{- define "nklave.pvcName" -}}
{{- printf "%s-data" (include "nklave.fullname" .) -}}
{{- end }}
