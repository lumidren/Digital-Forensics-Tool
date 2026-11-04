{{/* Common names and labels. */}}
{{- define "veritas.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "veritas.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "veritas.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "veritas.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: veritas
{{- with .Values.global.labels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/* Selector labels for one component: include "veritas.selector" (dict "ctx" $ "component" "api") */}}
{{- define "veritas.selector" -}}
app.kubernetes.io/name: {{ include "veritas.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "veritas.componentLabels" -}}
{{ include "veritas.labels" .ctx }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* Image reference: include "veritas.image" (dict "ctx" $ "image" .Values.api.image) */}}
{{- define "veritas.image" -}}
{{- $tag := default .ctx.Chart.AppVersion .ctx.Values.image.tag -}}
{{- if .image.digest -}}
{{- printf "%s/%s@%s" .ctx.Values.global.imageRegistry .image.repository .image.digest -}}
{{- else -}}
{{- printf "%s/%s:%s" .ctx.Values.global.imageRegistry .image.repository $tag -}}
{{- end -}}
{{- end -}}

{{- define "veritas.dataClaim" -}}
{{- default (printf "%s-data" (include "veritas.fullname" .)) .Values.persistence.existingClaim -}}
{{- end -}}

{{/* Environment shared by api, worker and CronJobs. */}}
{{- define "veritas.env" -}}
- name: VERITAS_DATA_DIR
  value: /var/lib/veritas
- name: AWS_REGION
  value: {{ .Values.global.awsRegion | quote }}
- name: AWS_DEFAULT_REGION
  value: {{ .Values.global.awsRegion | quote }}
- name: VERITAS_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secret.name }}
      key: VERITAS_DATABASE_URL
- name: VERITAS_TIMELINE_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secret.name }}
      key: VERITAS_TIMELINE_URL
- name: VERITAS_MASTER_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secret.name }}
      key: VERITAS_MASTER_KEY
- name: VERITAS_SERVICE_KEY_SEED
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secret.name }}
      key: VERITAS_SERVICE_KEY_SEED
      optional: true
{{- end -}}

{{- define "veritas.volumeMounts" -}}
- name: data
  mountPath: /var/lib/veritas
- name: tmp
  mountPath: /tmp
{{- end -}}

{{- define "veritas.dataVolume" -}}
- name: data
{{- if .Values.persistence.enabled }}
  persistentVolumeClaim:
    claimName: {{ include "veritas.dataClaim" . }}
{{- else }}
  emptyDir: {}
{{- end }}
{{- end -}}
