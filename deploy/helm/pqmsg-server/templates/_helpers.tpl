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
{{- $imageDigest := trim (toString (default "" .Values.image.digest)) -}}
{{- $imageTag := trim (toString (default "" .Values.image.tag)) -}}
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
  {{- if eq $imageDigest "" -}}
    {{- fail "pqmsg-server hardened deployments require image.digest pinned by sha256" -}}
  {{- end -}}
  {{- if not (regexMatch "^sha256:[a-f0-9]{64}$" $imageDigest) -}}
    {{- fail "pqmsg-server hardened deployments require image.digest in sha256:<64-hex> format" -}}
  {{- end -}}
  {{- if eq (lower $imageTag) "latest" -}}
    {{- fail "pqmsg-server hardened deployments reject mutable image.tag=latest" -}}
  {{- end -}}
{{- end -}}
{{- end -}}

{{- define "pqmsg-server.imageRef" -}}
{{- $repo := trim .Values.image.repository -}}
{{- $digest := trim (toString (default "" .Values.image.digest)) -}}
{{- $tag := trim (toString (default "" .Values.image.tag)) -}}
{{- if eq $repo "" -}}
  {{- fail "pqmsg-server image.repository is required" -}}
{{- end -}}
{{- if ne $digest "" -}}
  {{- printf "%s@%s" $repo $digest -}}
{{- else -}}
  {{- printf "%s:%s" $repo $tag -}}
{{- end -}}
{{- end -}}
