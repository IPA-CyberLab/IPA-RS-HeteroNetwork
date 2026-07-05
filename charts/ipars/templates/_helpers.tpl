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

{{- define "ipars.serviceAccountName" -}}
{{- if .Values.serviceAccount.name -}}
{{- .Values.serviceAccount.name -}}
{{- else -}}
{{- include "ipars.fullname" . -}}
{{- end -}}
{{- end -}}

{{- define "ipars.validateCidr" -}}
{{- $value := .value -}}
{{- $path := .path -}}
{{- $ipv4 := regexMatch "^([0-9]{1,3}\\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$" $value -}}
{{- $ipv6 := regexMatch "^[0-9A-Fa-f:.]+/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])$" $value -}}
{{- if not (or $ipv4 $ipv6) -}}
{{- fail (printf "%s entry %q must be an IPv4 or IPv6 CIDR" $path $value) -}}
{{- end -}}
{{- end -}}

{{- define "ipars.validateIPAddress" -}}
{{- $value := .value -}}
{{- $path := .path -}}
{{- $ipv4Octet := "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])" -}}
{{- $ipv4 := regexMatch (printf "^%s\\.%s\\.%s\\.%s$" $ipv4Octet $ipv4Octet $ipv4Octet $ipv4Octet) $value -}}
{{- $ipv6 := and (contains ":" $value) (regexMatch "^[0-9A-Fa-f:.]+$" $value) -}}
{{- if not (or $ipv4 $ipv6) -}}
{{- fail (printf "%s value %q must be an IPv4 or IPv6 address" $path $value) -}}
{{- end -}}
{{- end -}}

{{- define "ipars.validateExternalServiceIPAddress" -}}
{{- $value := printf "%v" .value -}}
{{- $path := .path -}}
{{- include "ipars.validateIPAddress" (dict "path" $path "value" $value) -}}
{{- if or (eq $value "0.0.0.0") (eq $value "::") (eq $value "0:0:0:0:0:0:0:0") -}}
{{- fail (printf "%s value %q must not be an unspecified address" $path $value) -}}
{{- end -}}
{{- if or (regexMatch "^127\\." $value) (eq $value "::1") (eq $value "0:0:0:0:0:0:0:1") -}}
{{- fail (printf "%s value %q must not be a loopback address" $path $value) -}}
{{- end -}}
{{- if or (regexMatch "^169\\.254\\." $value) (regexMatch "^[Ff][Ee][89AaBb][0-9A-Fa-f]:" $value) -}}
{{- fail (printf "%s value %q must not be a link-local address" $path $value) -}}
{{- end -}}
{{- if or (regexMatch "^(22[4-9]|23[0-9])\\." $value) (regexMatch "^[Ff][Ff]" $value) -}}
{{- fail (printf "%s value %q must not be a multicast address" $path $value) -}}
{{- end -}}
{{- if eq $value "255.255.255.255" -}}
{{- fail (printf "%s value %q must not be a broadcast address" $path $value) -}}
{{- end -}}
{{- end -}}

{{- define "ipars.validateLabelKey" -}}
{{- $key := .key -}}
{{- $path := .path -}}
{{- $parts := splitList "/" $key -}}
{{- if gt (len $parts) 2 -}}
{{- fail (printf "%s label key %q must contain at most one '/' separator" $path $key) -}}
{{- else if eq (len $parts) 2 -}}
{{- $prefix := index $parts 0 -}}
{{- $name := index $parts 1 -}}
{{- if or (eq $prefix "") (gt (len $prefix) 253) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*$" $prefix)) -}}
{{- fail (printf "%s label prefix %q must be a Kubernetes DNS subdomain" $path $prefix) -}}
{{- end -}}
{{- if or (eq $name "") (gt (len $name) 63) (not (regexMatch "^[A-Za-z0-9]([A-Za-z0-9_.-]*[A-Za-z0-9])?$" $name)) -}}
{{- fail (printf "%s label name %q must be a Kubernetes qualified name" $path $name) -}}
{{- end -}}
{{- else -}}
{{- $name := index $parts 0 -}}
{{- if or (eq $name "") (gt (len $name) 63) (not (regexMatch "^[A-Za-z0-9]([A-Za-z0-9_.-]*[A-Za-z0-9])?$" $name)) -}}
{{- fail (printf "%s label name %q must be a Kubernetes qualified name" $path $name) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "ipars.validateLabelValue" -}}
{{- $value := .value -}}
{{- $path := .path -}}
{{- if or (gt (len $value) 63) (and (ne $value "") (not (regexMatch "^[A-Za-z0-9]([A-Za-z0-9_.-]*[A-Za-z0-9])?$" $value))) -}}
{{- fail (printf "%s label value %q must be empty or a Kubernetes label value of at most 63 bytes" $path $value) -}}
{{- end -}}
{{- end -}}

{{- define "ipars.validateResourceQuantity" -}}
{{- $value := .value -}}
{{- $path := .path -}}
{{- if and (ne $value "") (or (gt (len $value) 64) (not (regexMatch "^[0-9]([0-9A-Za-z.+-]*[0-9A-Za-z])?$" $value))) -}}
{{- fail (printf "%s resource quantity %q must be a non-negative Kubernetes quantity without whitespace" $path $value) -}}
{{- end -}}
{{- end -}}

{{- define "ipars.validateNonNegativeInteger" -}}
{{- $value := .value -}}
{{- $path := .path -}}
{{- if and (ne $value "") (not (regexMatch "^([0-9]|[1-9][0-9]*)$" $value)) -}}
{{- fail (printf "%s %q must be a non-negative integer" $path $value) -}}
{{- end -}}
{{- end -}}

{{- define "ipars.validateNonNegativeInt64" -}}
{{- $value := .value -}}
{{- $path := .path -}}
{{- include "ipars.validateNonNegativeInteger" . -}}
{{- if and (ne $value "") (or (gt (len $value) 19) (and (eq (len $value) 19) (gt $value "9223372036854775807"))) -}}
{{- fail (printf "%s %q must be a non-negative int64" $path $value) -}}
{{- end -}}
{{- end -}}

{{- define "ipars.validateIntOrPercent" -}}
{{- $value := .value -}}
{{- $path := .path -}}
{{- if and (ne $value "") (not (regexMatch "^([0-9]|[1-9][0-9]*|[0-9]%|[1-9][0-9]%|100%)$" $value)) -}}
{{- fail (printf "%s %q must be a non-negative integer or percentage from 0%% to 100%%" $path $value) -}}
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
