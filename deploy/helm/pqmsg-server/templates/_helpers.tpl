{{- define "pqmsg-server.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "pqmsg-server.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "pqmsg-server.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "pqmsg-server.labels" -}}
app.kubernetes.io/name: {{ include "pqmsg-server.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "pqmsg-server.selectorLabels" -}}
app.kubernetes.io/name: {{ include "pqmsg-server.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
