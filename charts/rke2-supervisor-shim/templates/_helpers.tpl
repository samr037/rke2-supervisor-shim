{{- define "shim.name" -}}rke2-supervisor-shim{{- end -}}
{{- define "shim.namespace" -}}{{ .Values.namespace.name }}{{- end -}}
{{- define "shim.labels" -}}
app.kubernetes.io/name: {{ include "shim.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}
{{- define "shim.selectorLabels" -}}
app: {{ include "shim.name" . }}
{{- end -}}
{{- define "shim.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}
{{- define "shim.agentConfigMap" -}}
{{- if .Values.agentConfig.existingConfigMap }}{{ .Values.agentConfig.existingConfigMap }}{{ else }}{{ include "shim.name" . }}-agent-config{{ end -}}
{{- end -}}
