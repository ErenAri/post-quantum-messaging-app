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

{{- define "pqmsg-server.validateDeploymentContract" -}}
{{- $mode := lower (default "development" .Values.env.PQMSG_DEPLOYMENT_MODE) -}}
{{- $corsOrigins := toString (default "" .Values.env.PQMSG_CORS_ALLOWED_ORIGINS) -}}
{{- $postgresStorage := trim (toString (default "" .Values.env.PQMSG_POSTGRES_STORAGE_ENCRYPTION)) -}}
{{- $postgresBackups := lower (trim (toString (default "" .Values.env.PQMSG_POSTGRES_BACKUP_ENCRYPTION))) -}}
{{- $databaseUrl := trim (toString (default "" .Values.secretEnv.PQMSG_DATABASE_URL)) -}}
{{- $redisUrl := trim (toString (default "" .Values.secretEnv.PQMSG_RATE_LIMIT_REDIS_URL)) -}}
{{- $sentryDsn := trim (toString (default "" .Values.secretEnv.PQMSG_SENTRY_DSN)) -}}
{{- if or (eq $mode "pilot") (eq $mode "production") -}}
  {{- if eq $postgresStorage "" -}}
    {{- fail "pqmsg-server hardened deployments require env.PQMSG_POSTGRES_STORAGE_ENCRYPTION" -}}
  {{- end -}}
  {{- if ne $postgresBackups "true" -}}
    {{- fail "pqmsg-server hardened deployments require env.PQMSG_POSTGRES_BACKUP_ENCRYPTION=true" -}}
  {{- end -}}
  {{- if contains "*" $corsOrigins -}}
    {{- fail "pqmsg-server hardened deployments reject wildcard env.PQMSG_CORS_ALLOWED_ORIGINS" -}}
  {{- end -}}
  {{- if eq $databaseUrl "" -}}
    {{- fail "pqmsg-server hardened deployments require secretEnv.PQMSG_DATABASE_URL" -}}
  {{- end -}}
  {{- if eq $redisUrl "" -}}
    {{- fail "pqmsg-server hardened deployments require secretEnv.PQMSG_RATE_LIMIT_REDIS_URL" -}}
  {{- end -}}
{{- end -}}
{{- if eq $mode "production" -}}
  {{- if eq $sentryDsn "" -}}
    {{- fail "pqmsg-server production deployments require secretEnv.PQMSG_SENTRY_DSN" -}}
  {{- end -}}
{{- end -}}
{{- end -}}
