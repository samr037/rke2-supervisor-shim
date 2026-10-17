{{- define "shim.name" -}}rke2-supervisor-shim{{- end -}}
{{- define "shim.namespace" -}}{{ .Values.namespace.name }}{{- end -}}
{{- define "shim.labels" -}}
app.kubernetes.io/name: {{ include "shim.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}
{{- define "shim.serviceAccountName" -}}{{ include "shim.name" . }}{{- end -}}
{{- define "shim.selectorLabels" -}}
app: {{ include "shim.name" . }}
{{- end -}}
{{/*
A digest, when given, wins over the tag: it is the only reference that cannot
be repointed after `cosign verify` / `gh attestation verify` checked it.
*/}}
{{- define "shim.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}
{{- end -}}
{{- define "shim.agentConfigMap" -}}
{{- if .Values.agentConfig.existingConfigMap }}{{ .Values.agentConfig.existingConfigMap }}{{ else }}{{ include "shim.name" . }}-agent-config{{ end -}}
{{- end -}}
{{/*
"auto" renders the ValidatingAdmissionPolicy only when the target cluster
serves it at v1 (GA in Kubernetes 1.30). Under `helm template` with no cluster
this follows Helm's built-in API list unless --api-versions/--kube-version are
passed, so check the rendered output rather than assuming.
*/}}
{{- define "shim.secretsAdmissionPolicy.enabled" -}}
{{- $v := toString .Values.secretsAdmissionPolicy.enabled -}}
{{- if eq $v "auto" -}}
{{- if and (.Capabilities.APIVersions.Has "admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy") (semverCompare ">=1.30.0-0" .Capabilities.KubeVersion.Version) -}}true{{- end -}}
{{- else if eq $v "true" -}}true
{{- end -}}
{{- end -}}

{{/* Same auto-detection for the rke2-controller node policy. */}}
{{- define "shim.nodesAdmissionPolicy.enabled" -}}
{{- $v := toString .Values.rke2ControllerAdmissionPolicy.enabled -}}
{{- if eq $v "auto" -}}
{{- if and (.Capabilities.APIVersions.Has "admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy") (semverCompare ">=1.30.0-0" .Capabilities.KubeVersion.Version) -}}true{{- end -}}
{{- else if eq $v "true" -}}true
{{- end -}}
{{- end -}}
