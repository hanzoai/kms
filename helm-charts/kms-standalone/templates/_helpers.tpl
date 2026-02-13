{{/*
Expand the name of the chart.
*/}}
{{- define "kms.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "kms.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create unified labels for kms components
*/}}
{{- define "kms.common.matchLabels" -}}
app: {{ template "kms.name" . }}
release: {{ .Release.Name }}
{{- end -}}

{{- define "kms.common.metaLabels" -}}
chart: {{ template "kms.chart" . }}
heritage: {{ .Release.Service }}
{{- end -}}

{{- define "kms.common.labels" -}}
{{ include "kms.common.matchLabels" . }}
{{ include "kms.common.metaLabels" . }}
{{- end -}}

{{- define "kms.labels" -}}
{{ include "kms.matchLabels" . }}
{{ include "kms.common.metaLabels" . }}
{{- end -}}

{{- define "kms.matchLabels" -}}
component: {{ .Values.kms.name | quote }}
{{ include "kms.common.matchLabels" . }}
{{- end -}}

{{- define "kms.roleName" -}}
{{- printf "%s-kms" .Release.Name -}}
{{- end -}}

{{- define "kms.roleBindingName" -}}
{{- printf "%s-kms" .Release.Name -}}
{{- end -}}

{{- define "kms.serviceAccountName" -}}
{{- if .Values.kms.serviceAccount.create -}}
{{- printf "%s-kms" .Release.Name -}}
{{- else -}}
{{- .Values.kms.serviceAccount.name | default "default" -}}
{{- end -}}
{{- end -}}


{{/*
Create a fully qualified backend name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "kms.fullname" -}}
{{- if .Values.kms.fullnameOverride -}}
{{- .Values.kms.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- printf "%s-%s" .Release.Name .Values.kms.name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s-%s" .Release.Name $name .Values.kms.name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "kms.postgresService" -}}
{{- if .Values.postgresql.fullnameOverride -}}
{{- .Values.postgresql.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-postgresql" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "kms.postgresDBConnectionString" -}}
{{- $dbUsername := .Values.postgresql.auth.username -}}
{{- $dbPassword := .Values.postgresql.auth.password -}}
{{- $dbName := .Values.postgresql.auth.database -}}
{{- $serviceName := include "kms.postgresService" . -}}
{{- printf "postgresql://%s:%s@%s:5432/%s" $dbUsername $dbPassword $serviceName $dbName -}}
{{- end -}}

{{/*
Create a fully qualified redis name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "kms.redis.fullname" -}}
{{- if .Values.redis.fullnameOverride -}}
{{- .Values.redis.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- printf "%s-%s" .Release.Name .Values.redis.name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s-%s" .Release.Name $name .Values.redis.name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}


{{- define "kms.redisServiceName" -}}
{{- if .Values.redis.fullnameOverride -}}
{{- printf "%s-master" .Values.redis.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-master" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}


{{- define "kms.redisConnectionString" -}}
{{- $password := .Values.redis.auth.password -}}
{{- $serviceName := include "kms.redisServiceName" . -}}
{{- printf "redis://default:%s@%s:6379" $password "redis-master" -}}
{{- end -}}