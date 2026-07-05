{{- define "ipars.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ipars.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- include "ipars.name" . -}}
{{- end -}}
{{- end -}}

{{- define "ipars.validateAnnotationKey" -}}
{{- $key := .key -}}
{{- $path := .path -}}
{{- $parts := splitList "/" $key -}}
{{- if gt (len $parts) 2 -}}
{{- fail (printf "%s annotation key %q must contain at most one '/' separator" $path $key) -}}
{{- else if eq (len $parts) 2 -}}
{{- $prefix := index $parts 0 -}}
{{- $name := index $parts 1 -}}
{{- if or (eq $prefix "") (gt (len $prefix) 253) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*$" $prefix)) -}}
{{- fail (printf "%s annotation prefix %q must be a Kubernetes DNS subdomain" $path $prefix) -}}
{{- end -}}
{{- if or (eq $name "") (gt (len $name) 63) (not (regexMatch "^[A-Za-z0-9]([A-Za-z0-9_.-]*[A-Za-z0-9])?$" $name)) -}}
{{- fail (printf "%s annotation name %q must be a Kubernetes qualified name" $path $name) -}}
{{- end -}}
{{- else -}}
{{- $name := index $parts 0 -}}
{{- if or (eq $name "") (gt (len $name) 63) (not (regexMatch "^[A-Za-z0-9]([A-Za-z0-9_.-]*[A-Za-z0-9])?$" $name)) -}}
{{- fail (printf "%s annotation name %q must be a Kubernetes qualified name" $path $name) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "ipars.validateOptionalQualifiedNameWithPrefix" -}}
{{- $value := .value -}}
{{- $path := .path -}}
{{- if ne $value "" -}}
{{- $parts := splitList "/" $value -}}
{{- if gt (len $parts) 2 -}}
{{- fail (printf "%s %q must contain at most one '/' separator" $path $value) -}}
{{- else if eq (len $parts) 2 -}}
{{- $prefix := index $parts 0 -}}
{{- $name := index $parts 1 -}}
{{- if or (eq $prefix "") (gt (len $prefix) 253) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*$" $prefix)) -}}
{{- fail (printf "%s prefix %q must be a Kubernetes DNS subdomain" $path $prefix) -}}
{{- end -}}
{{- if or (eq $name "") (gt (len $name) 63) (not (regexMatch "^[A-Za-z0-9]([A-Za-z0-9_.-]*[A-Za-z0-9])?$" $name)) -}}
{{- fail (printf "%s name %q must be a Kubernetes qualified name" $path $name) -}}
{{- end -}}
{{- else -}}
{{- $name := index $parts 0 -}}
{{- if or (eq $name "") (gt (len $name) 63) (not (regexMatch "^[A-Za-z0-9]([A-Za-z0-9_.-]*[A-Za-z0-9])?$" $name)) -}}
{{- fail (printf "%s name %q must be a Kubernetes qualified name" $path $name) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
