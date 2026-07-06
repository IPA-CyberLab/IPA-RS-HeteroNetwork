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

{{- define "ipars.validateDnsLabelWithMax" -}}
{{- $value := printf "%v" .value -}}
{{- $path := .path -}}
{{- $maxBytes := int .maxBytes -}}
{{- if or (eq $value "") (gt (len $value) $maxBytes) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $value)) -}}
{{- fail (printf "%s %q must be a DNS label of at most %d bytes using lowercase ASCII letters, digits, and '-' with alphanumeric edges" $path $value $maxBytes) -}}
{{- end -}}
{{- end -}}

{{- define "ipars.validateChartMetadata" -}}
{{- include "ipars.validateDnsLabelWithMax" (dict "path" "Release.Name" "value" .Release.Name "maxBytes" 53) -}}
{{- include "ipars.validateDnsLabelWithMax" (dict "path" "Release.Namespace" "value" .Release.Namespace "maxBytes" 63) -}}
{{- $nameOverride := printf "%v" (default "" .Values.nameOverride) -}}
{{- $fullnameOverride := printf "%v" (default "" .Values.fullnameOverride) -}}
{{- if ne $nameOverride "" -}}
{{- include "ipars.validateDnsLabelWithMax" (dict "path" "nameOverride" "value" $nameOverride "maxBytes" 53) -}}
{{- end -}}
{{- if ne $fullnameOverride "" -}}
{{- include "ipars.validateDnsLabelWithMax" (dict "path" "fullnameOverride" "value" $fullnameOverride "maxBytes" 53) -}}
{{- end -}}
{{- end -}}

{{- define "ipars.validateCidr" -}}
{{- $value := .value -}}
{{- $path := .path -}}
{{- $ipv4Octet := "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])" -}}
{{- $ipv4 := regexMatch (printf "^%s\\.%s\\.%s\\.%s/([0-9]|[1-2][0-9]|3[0-2])$" $ipv4Octet $ipv4Octet $ipv4Octet $ipv4Octet) $value -}}
{{- $ipv6 := regexMatch "^[0-9A-Fa-f:.]+/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])$" $value -}}
{{- if not (or $ipv4 $ipv6) -}}
{{- fail (printf "%s entry %q must be an IPv4 or IPv6 CIDR" $path $value) -}}
{{- end -}}
{{- end -}}

{{- define "ipars.validateRestrictedCidr" -}}
{{- $value := printf "%v" .value -}}
{{- $path := .path -}}
{{- include "ipars.validateCidr" (dict "path" $path "value" $value) -}}
{{- if or (eq $value "0.0.0.0/0") (regexMatch "^[0:]+/0$" $value) -}}
{{- fail (printf "%s entry %q must not be an unrestricted CIDR" $path $value) -}}
{{- end -}}
{{- if regexMatch "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+$" $value -}}
{{- $parts := splitList "/" $value -}}
{{- $octets := splitList "." (index $parts 0) -}}
{{- $prefix := int (index $parts 1) -}}
{{- $ip := add (mul (int (index $octets 0)) 16777216) (mul (int (index $octets 1)) 65536) (mul (int (index $octets 2)) 256) (int (index $octets 3)) -}}
{{- $blockSizes := list 4294967296 2147483648 1073741824 536870912 268435456 134217728 67108864 33554432 16777216 8388608 4194304 2097152 1048576 524288 262144 131072 65536 32768 16384 8192 4096 2048 1024 512 256 128 64 32 16 8 4 2 1 -}}
{{- $size := int (index $blockSizes $prefix) -}}
{{- $start := mul (div $ip $size) $size -}}
{{- $end := add $start (sub $size 1) -}}
{{- if ne $ip $start -}}
{{- fail (printf "%s entry %q must be a canonical IPv4 CIDR" $path $value) -}}
{{- end -}}
{{- if and (le $start 16777215) (le 0 $end) -}}
{{- fail (printf "%s entry %q must not include unspecified CIDRs" $path $value) -}}
{{- end -}}
{{- if and (le $start 2147483647) (le 2130706432 $end) -}}
{{- fail (printf "%s entry %q must not include loopback CIDRs" $path $value) -}}
{{- end -}}
{{- if and (le $start 2852061183) (le 2851995648 $end) -}}
{{- fail (printf "%s entry %q must not include link-local CIDRs" $path $value) -}}
{{- end -}}
{{- if and (le $start 4026531839) (le 3758096384 $end) -}}
{{- fail (printf "%s entry %q must not include multicast CIDRs" $path $value) -}}
{{- end -}}
{{- if and (le $start 4294967295) (le 4294967295 $end) -}}
{{- fail (printf "%s entry %q must not include broadcast CIDRs" $path $value) -}}
{{- end -}}
{{- else if contains ":" $value -}}
{{- if regexMatch "^([0:]+|0*:)/" $value -}}
{{- fail (printf "%s entry %q must not include unspecified CIDRs" $path $value) -}}
{{- end -}}
{{- if or (regexMatch "^::1/" $value) (regexMatch "^0:0:0:0:0:0:0:1/" $value) -}}
{{- fail (printf "%s entry %q must not include loopback CIDRs" $path $value) -}}
{{- end -}}
{{- if regexMatch "^[Ff][Ee][89AaBb][0-9A-Fa-f]:" $value -}}
{{- fail (printf "%s entry %q must not include link-local CIDRs" $path $value) -}}
{{- end -}}
{{- if regexMatch "^[Ff][Ff]" $value -}}
{{- fail (printf "%s entry %q must not include multicast CIDRs" $path $value) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "ipars.validateKubernetesRouteCidr" -}}
{{- $value := printf "%v" .value -}}
{{- $path := .path -}}
{{- include "ipars.validateRestrictedCidr" (dict "path" $path "value" $value) -}}
{{- if regexMatch "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+$" $value -}}
{{- $parts := splitList "/" $value -}}
{{- $octets := splitList "." (index $parts 0) -}}
{{- $prefix := int (index $parts 1) -}}
{{- $ip := add (mul (int (index $octets 0)) 16777216) (mul (int (index $octets 1)) 65536) (mul (int (index $octets 2)) 256) (int (index $octets 3)) -}}
{{- $blockSizes := list 4294967296 2147483648 1073741824 536870912 268435456 134217728 67108864 33554432 16777216 8388608 4194304 2097152 1048576 524288 262144 131072 65536 32768 16384 8192 4096 2048 1024 512 256 128 64 32 16 8 4 2 1 -}}
{{- $size := int (index $blockSizes $prefix) -}}
{{- $start := mul (div $ip $size) $size -}}
{{- $end := add $start (sub $size 1) -}}
{{- if ne $ip $start -}}
{{- fail (printf "%s entry %q must be a canonical IPv4 CIDR route" $path $value) -}}
{{- end -}}
{{- if and (le $start 16777215) (le 0 $end) -}}
{{- fail (printf "%s entry %q must not include unspecified route CIDRs" $path $value) -}}
{{- end -}}
{{- if and (le $start 2147483647) (le 2130706432 $end) -}}
{{- fail (printf "%s entry %q must not include loopback route CIDRs" $path $value) -}}
{{- end -}}
{{- if and (le $start 2852061183) (le 2851995648 $end) -}}
{{- fail (printf "%s entry %q must not include link-local route CIDRs" $path $value) -}}
{{- end -}}
{{- if and (le $start 4026531839) (le 3758096384 $end) -}}
{{- fail (printf "%s entry %q must not include multicast route CIDRs" $path $value) -}}
{{- end -}}
{{- if and (le $start 4294967295) (le 4294967295 $end) -}}
{{- fail (printf "%s entry %q must not include broadcast route CIDRs" $path $value) -}}
{{- end -}}
{{- else if contains ":" $value -}}
{{- if regexMatch "^([0:]+|0*:)/" $value -}}
{{- fail (printf "%s entry %q must not include unspecified route CIDRs" $path $value) -}}
{{- end -}}
{{- if or (regexMatch "^::1/" $value) (regexMatch "^0:0:0:0:0:0:0:1/" $value) -}}
{{- fail (printf "%s entry %q must not include loopback route CIDRs" $path $value) -}}
{{- end -}}
{{- if regexMatch "^[Ff][Ee][89AaBb][0-9A-Fa-f]:" $value -}}
{{- fail (printf "%s entry %q must not include link-local route CIDRs" $path $value) -}}
{{- end -}}
{{- if regexMatch "^[Ff][Ff]" $value -}}
{{- fail (printf "%s entry %q must not include multicast route CIDRs" $path $value) -}}
{{- end -}}
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

{{- define "ipars.validateUsableServiceIPAddress" -}}
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

{{- define "ipars.validateExternalServiceIPAddress" -}}
{{- include "ipars.validateUsableServiceIPAddress" . -}}
{{- end -}}

{{- define "ipars.validateBoolean" -}}
{{- $path := .path -}}
{{- if not (kindIs "bool" .value) -}}
{{- fail (printf "%s must be true or false" $path) -}}
{{- end -}}
{{- end -}}

{{- define "ipars.validateOptionalBoolean" -}}
{{- $path := .path -}}
{{- if and (not (kindIs "bool" .value)) (ne (printf "%v" .value) "") -}}
{{- fail (printf "%s must be true, false, or empty" $path) -}}
{{- end -}}
{{- end -}}

{{- define "ipars.validateHttpEndpointURL" -}}
{{- $value := printf "%v" .value -}}
{{- $path := .path -}}
{{- if not (regexMatch "^https?://[^/[:space:]?#]+[^[:space:]]*$" $value) -}}
{{- fail (printf "%s must be an absolute HTTP(S) URL with a host" $path) -}}
{{- end -}}
{{- $authorityWithScheme := regexFind "^https?://[^/[:space:]?#]+" $value -}}
{{- $authority := trimPrefix "https://" (trimPrefix "http://" $authorityWithScheme) -}}
{{- if contains "@" $authority -}}
{{- fail (printf "%s must not include userinfo" $path) -}}
{{- end -}}
{{- if hasPrefix "[" $authority -}}
{{- if not (regexMatch "^\\[[0-9A-Fa-f:.]+\\](:[0-9]+)?$" $authority) -}}
{{- fail (printf "%s host must be a bracketed IPv6 address with an optional numeric port" $path) -}}
{{- end -}}
{{- if regexMatch ":[0-9]+$" $authority -}}
{{- $port := int (trimPrefix ":" (regexFind ":[0-9]+$" $authority)) -}}
{{- if or (lt $port 1) (gt $port 65535) -}}
{{- fail (printf "%s port must be between 1 and 65535" $path) -}}
{{- end -}}
{{- end -}}
{{- $host := trimSuffix "]" (trimPrefix "[" (regexFind "^\\[[^\\]]+\\]" $authority)) -}}
{{- if regexMatch "^[0:]+$" $host -}}
{{- fail (printf "%s host must not be an unspecified address" $path) -}}
{{- end -}}
{{- if regexMatch "^[Ff][Ff]" $host -}}
{{- fail (printf "%s host must not be a multicast address" $path) -}}
{{- end -}}
{{- else -}}
{{- if not (regexMatch "^[^:]+(:[0-9]+)?$" $authority) -}}
{{- fail (printf "%s host must include an optional numeric port only" $path) -}}
{{- end -}}
{{- if regexMatch ":[0-9]+$" $authority -}}
{{- $port := int (trimPrefix ":" (regexFind ":[0-9]+$" $authority)) -}}
{{- if or (lt $port 1) (gt $port 65535) -}}
{{- fail (printf "%s port must be between 1 and 65535" $path) -}}
{{- end -}}
{{- end -}}
{{- $host := regexFind "^[^:]+" $authority -}}
{{- $ipv4Octet := "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])" -}}
{{- if regexMatch (printf "^%s\\.%s\\.%s\\.%s$" $ipv4Octet $ipv4Octet $ipv4Octet $ipv4Octet) $host -}}
{{- if eq $host "0.0.0.0" -}}
{{- fail (printf "%s host must not be an unspecified address" $path) -}}
{{- end -}}
{{- if regexMatch "^(22[4-9]|23[0-9])\\." $host -}}
{{- fail (printf "%s host must not be a multicast address" $path) -}}
{{- end -}}
{{- if eq $host "255.255.255.255" -}}
{{- fail (printf "%s host must not be a broadcast address" $path) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "ipars.validateSocketAddress" -}}
{{- $value := printf "%v" .value -}}
{{- $path := .path -}}
{{- $ipv4Octet := "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])" -}}
{{- $ipv4Socket := regexMatch (printf "^%s\\.%s\\.%s\\.%s:[0-9]+$" $ipv4Octet $ipv4Octet $ipv4Octet $ipv4Octet) $value -}}
{{- $ipv6Socket := regexMatch "^\\[[0-9A-Fa-f:.]+\\]:[0-9]+$" $value -}}
{{- if not (or $ipv4Socket $ipv6Socket) -}}
{{- fail (printf "%s value %q must be an IPv4 host:port or [IPv6]:port socket address" $path $value) -}}
{{- end -}}
{{- $port := int (regexFind "[0-9]+$" $value) -}}
{{- if or (lt $port 1) (gt $port 65535) -}}
{{- fail (printf "%s port must be between 1 and 65535" $path) -}}
{{- end -}}
{{- if $ipv4Socket -}}
{{- $host := regexFind "^[^:]+" $value -}}
{{- if eq $host "0.0.0.0" -}}
{{- fail (printf "%s value %q must not use an unspecified address" $path $value) -}}
{{- end -}}
{{- if regexMatch "^(22[4-9]|23[0-9])\\." $host -}}
{{- fail (printf "%s value %q must not use a multicast address" $path $value) -}}
{{- end -}}
{{- if eq $host "255.255.255.255" -}}
{{- fail (printf "%s value %q must not use a broadcast address" $path $value) -}}
{{- end -}}
{{- else if $ipv6Socket -}}
{{- $host := trimSuffix "]" (trimPrefix "[" (regexFind "^\\[[^\\]]+\\]" $value)) -}}
{{- if regexMatch "^[0:]+$" $host -}}
{{- fail (printf "%s value %q must not use an unspecified address" $path $value) -}}
{{- end -}}
{{- if regexMatch "^[Ff][Ff]" $host -}}
{{- fail (printf "%s value %q must not use a multicast address" $path $value) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "ipars.validateBindSocketAddress" -}}
{{- $value := printf "%v" .value -}}
{{- $path := .path -}}
{{- $ipv4Octet := "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])" -}}
{{- $ipv4Socket := regexMatch (printf "^%s\\.%s\\.%s\\.%s:[0-9]+$" $ipv4Octet $ipv4Octet $ipv4Octet $ipv4Octet) $value -}}
{{- $ipv6Socket := regexMatch "^\\[[0-9A-Fa-f:.]+\\]:[0-9]+$" $value -}}
{{- if not (or $ipv4Socket $ipv6Socket) -}}
{{- fail (printf "%s value %q must be an IPv4 host:port or [IPv6]:port bind socket address" $path $value) -}}
{{- end -}}
{{- $port := int (regexFind "[0-9]+$" $value) -}}
{{- if or (lt $port 1) (gt $port 65535) -}}
{{- fail (printf "%s port must be between 1 and 65535" $path) -}}
{{- end -}}
{{- if $ipv4Socket -}}
{{- $host := regexFind "^[^:]+" $value -}}
{{- if regexMatch "^(22[4-9]|23[0-9])\\." $host -}}
{{- fail (printf "%s value %q must not use a multicast bind address" $path $value) -}}
{{- end -}}
{{- if eq $host "255.255.255.255" -}}
{{- fail (printf "%s value %q must not use a broadcast bind address" $path $value) -}}
{{- end -}}
{{- else if $ipv6Socket -}}
{{- $host := trimSuffix "]" (trimPrefix "[" (regexFind "^\\[[^\\]]+\\]" $value)) -}}
{{- if regexMatch "^[Ff][Ff]" $host -}}
{{- fail (printf "%s value %q must not use a multicast bind address" $path $value) -}}
{{- end -}}
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

{{- define "ipars.validateNonNegativeIntegerMax" -}}
{{- $value := .value -}}
{{- $path := .path -}}
{{- $max := printf "%v" .max -}}
{{- if eq $value "" -}}
{{- fail (printf "%s must be a non-negative integer" $path) -}}
{{- end -}}
{{- include "ipars.validateOptionalNonNegativeIntegerMax" . -}}
{{- end -}}

{{- define "ipars.validateOptionalNonNegativeIntegerMax" -}}
{{- $value := .value -}}
{{- $path := .path -}}
{{- $max := printf "%v" .max -}}
{{- include "ipars.validateNonNegativeInteger" . -}}
{{- if or (gt (len $value) (len $max)) (and (eq (len $value) (len $max)) (gt $value $max)) -}}
{{- fail (printf "%s must be a non-negative integer no greater than %s" $path $max) -}}
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
{{- if and (ne $value "") (not (regexMatch "%$" $value)) (or (gt (len $value) 10) (and (eq (len $value) 10) (gt $value "2147483647"))) -}}
{{- fail (printf "%s %q must be a non-negative IntOrString integer no greater than 2147483647" $path $value) -}}
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

{{- define "ipars.validateAnnotationValue" -}}
{{- $rawValue := .value -}}
{{- $path := .path -}}
{{- if not (kindIs "string" $rawValue) -}}
{{- fail (printf "%s annotation value must be a string" $path) -}}
{{- end -}}
{{- $value := printf "%v" $rawValue -}}
{{- if gt (len $value) 262144 -}}
{{- fail (printf "%s annotation value exceeds 262144 bytes" $path) -}}
{{- end -}}
{{- if regexMatch "[[:cntrl:]]" $value -}}
{{- fail (printf "%s annotation value must not contain control characters" $path) -}}
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
