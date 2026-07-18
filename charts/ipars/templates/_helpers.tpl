{{- define "heteronetwork.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "heteronetwork.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 53 | trimSuffix "-" -}}
{{- else -}}
{{- $name := include "heteronetwork.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 53 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 53 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "heteronetwork.serviceAccountName" -}}
{{- if .Values.serviceAccount.name -}}
{{- .Values.serviceAccount.name -}}
{{- else -}}
{{- include "heteronetwork.fullname" . -}}
{{- end -}}
{{- end -}}

{{- define "heteronetwork.validateDnsLabelWithMax" -}}
{{- $value := printf "%v" .value -}}
{{- $path := .path -}}
{{- $maxBytes := int .maxBytes -}}
{{- if or (eq $value "") (gt (len $value) $maxBytes) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $value)) -}}
{{- fail (printf "%s %q must be a DNS label of at most %d bytes using lowercase ASCII letters, digits, and '-' with alphanumeric edges" $path $value $maxBytes) -}}
{{- end -}}
{{- end -}}

{{- define "heteronetwork.validateChartMetadata" -}}
{{- include "heteronetwork.validateDnsLabelWithMax" (dict "path" "Release.Name" "value" .Release.Name "maxBytes" 53) -}}
{{- include "heteronetwork.validateDnsLabelWithMax" (dict "path" "Release.Namespace" "value" .Release.Namespace "maxBytes" 63) -}}
{{- $nameOverride := printf "%v" (default "" .Values.nameOverride) -}}
{{- $fullnameOverride := printf "%v" (default "" .Values.fullnameOverride) -}}
{{- if ne $nameOverride "" -}}
{{- include "heteronetwork.validateDnsLabelWithMax" (dict "path" "nameOverride" "value" $nameOverride "maxBytes" 53) -}}
{{- end -}}
{{- if ne $fullnameOverride "" -}}
{{- include "heteronetwork.validateDnsLabelWithMax" (dict "path" "fullnameOverride" "value" $fullnameOverride "maxBytes" 53) -}}
{{- end -}}
{{- end -}}

{{- define "heteronetwork.validateCidr" -}}
{{- $value := .value -}}
{{- $path := .path -}}
{{- $ipv4Octet := "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])" -}}
{{- $ipv4 := regexMatch (printf "^%s\\.%s\\.%s\\.%s/([0-9]|[1-2][0-9]|3[0-2])$" $ipv4Octet $ipv4Octet $ipv4Octet $ipv4Octet) $value -}}
{{- $ipv6 := and (contains ":" $value) (regexMatch "^[0-9A-Fa-f:.]+/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])$" $value) -}}
{{- if not (or $ipv4 $ipv6) -}}
{{- fail (printf "%s entry %q must be an IPv4 or IPv6 CIDR" $path $value) -}}
{{- end -}}
{{- if $ipv6 -}}
{{- $parts := splitList "/" $value -}}
{{- $_ := include "heteronetwork.ipv6AddressNibbles" (dict "path" $path "value" (index $parts 0)) -}}
{{- end -}}
{{- end -}}

{{- define "heteronetwork.validateRestrictedCidr" -}}
{{- $value := printf "%v" .value -}}
{{- $path := .path -}}
{{- include "heteronetwork.validateCidr" (dict "path" $path "value" $value) -}}
{{- if or (eq $value "0.0.0.0/0") (and (contains ":" $value) (regexMatch "/0$" $value)) -}}
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
{{- $parts := splitList "/" $value -}}
{{- $prefix := int (index $parts 1) -}}
{{- $bits := include "heteronetwork.ipv6CidrBits" (dict "path" $path "value" $value) -}}
{{- if regexMatch "1" (substr $prefix 128 $bits) -}}
{{- fail (printf "%s entry %q must be a canonical IPv6 CIDR" $path $value) -}}
{{- end -}}
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

{{- define "heteronetwork.ipv4CidrRange" -}}
{{- $value := printf "%v" .value -}}
{{- if regexMatch "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+$" $value -}}
{{- $parts := splitList "/" $value -}}
{{- $octets := splitList "." (index $parts 0) -}}
{{- $prefix := int (index $parts 1) -}}
{{- $ip := add (mul (int (index $octets 0)) 16777216) (mul (int (index $octets 1)) 65536) (mul (int (index $octets 2)) 256) (int (index $octets 3)) -}}
{{- $blockSizes := list 4294967296 2147483648 1073741824 536870912 268435456 134217728 67108864 33554432 16777216 8388608 4194304 2097152 1048576 524288 262144 131072 65536 32768 16384 8192 4096 2048 1024 512 256 128 64 32 16 8 4 2 1 -}}
{{- $size := int (index $blockSizes $prefix) -}}
{{- $start := mul (div $ip $size) $size -}}
{{- $end := add $start (sub $size 1) -}}
{{- printf "%d:%d" $start $end -}}
{{- end -}}
{{- end -}}

{{- define "heteronetwork.hexNibbleBits" -}}
{{- $value := lower (printf "%v" .value) -}}
{{- $path := default "IPv6 address" .path -}}
{{- $bitsByNibble := dict "0" "0000" "1" "0001" "2" "0010" "3" "0011" "4" "0100" "5" "0101" "6" "0110" "7" "0111" "8" "1000" "9" "1001" "a" "1010" "b" "1011" "c" "1100" "d" "1101" "e" "1110" "f" "1111" -}}
{{- if not (hasKey $bitsByNibble $value) -}}
{{- fail (printf "%s contains invalid IPv6 hex nibble %q" $path $value) -}}
{{- end -}}
{{- get $bitsByNibble $value -}}
{{- end -}}

{{- define "heteronetwork.ipv6AddressNibbles" -}}
{{- $address := printf "%v" .value -}}
{{- $path := default "IPv6 address" .path -}}
{{- if contains "." $address -}}
{{- fail (printf "%s value %q must not use embedded IPv4 notation" $path $address) -}}
{{- end -}}
{{- $compressedParts := splitList "::" $address -}}
{{- if gt (len $compressedParts) 2 -}}
{{- fail (printf "%s value %q must contain at most one '::' compression" $path $address) -}}
{{- end -}}
{{- $hasCompression := contains "::" $address -}}
{{- $headRaw := index $compressedParts 0 -}}
{{- $tailRaw := "" -}}
{{- if eq (len $compressedParts) 2 -}}
{{- $tailRaw = index $compressedParts 1 -}}
{{- end -}}
{{- $hextets := list -}}
{{- if ne $headRaw "" -}}
{{- range $part := splitList ":" $headRaw -}}
{{- if or (eq $part "") (not (regexMatch "^[0-9A-Fa-f]{1,4}$" $part)) -}}
{{- fail (printf "%s value %q contains invalid IPv6 hextet %q" $path $address $part) -}}
{{- end -}}
{{- $hextets = append $hextets $part -}}
{{- end -}}
{{- end -}}
{{- $tailHextets := list -}}
{{- if and $hasCompression (ne $tailRaw "") -}}
{{- range $part := splitList ":" $tailRaw -}}
{{- if or (eq $part "") (not (regexMatch "^[0-9A-Fa-f]{1,4}$" $part)) -}}
{{- fail (printf "%s value %q contains invalid IPv6 hextet %q" $path $address $part) -}}
{{- end -}}
{{- $tailHextets = append $tailHextets $part -}}
{{- end -}}
{{- end -}}
{{- if $hasCompression -}}
{{- $missing := sub 8 (add (len $hextets) (len $tailHextets)) -}}
{{- if lt $missing 1 -}}
{{- fail (printf "%s value %q has too many IPv6 hextets" $path $address) -}}
{{- end -}}
{{- range until (int $missing) -}}
{{- $hextets = append $hextets "0" -}}
{{- end -}}
{{- range $part := $tailHextets -}}
{{- $hextets = append $hextets $part -}}
{{- end -}}
{{- else if ne (len $hextets) 8 -}}
{{- fail (printf "%s value %q must contain exactly eight IPv6 hextets or use '::' compression" $path $address) -}}
{{- end -}}
{{- if ne (len $hextets) 8 -}}
{{- fail (printf "%s value %q must expand to exactly eight IPv6 hextets" $path $address) -}}
{{- end -}}
{{- $out := dict "value" "" -}}
{{- range $part := $hextets -}}
{{- $lowerPart := lower (printf "%v" $part) -}}
{{- $_ := set $out "value" (printf "%s%s%s" (get $out "value") (repeat (int (sub 4 (len $lowerPart))) "0") $lowerPart) -}}
{{- end -}}
{{- get $out "value" -}}
{{- end -}}

{{- define "heteronetwork.ipv6CidrBits" -}}
{{- $value := printf "%v" .value -}}
{{- $path := .path -}}
{{- $parts := splitList "/" $value -}}
{{- if ne (len $parts) 2 -}}
{{- fail (printf "%s entry %q must be an IPv6 CIDR" $path $value) -}}
{{- end -}}
{{- $nibbles := include "heteronetwork.ipv6AddressNibbles" (dict "path" $path "value" (index $parts 0)) -}}
{{- $out := dict "value" "" -}}
{{- range $idx := until (len $nibbles) -}}
{{- $nibble := substr $idx (int (add $idx 1)) $nibbles -}}
{{- $_ := set $out "value" (printf "%s%s" (get $out "value") (include "heteronetwork.hexNibbleBits" (dict "path" $path "value" $nibble))) -}}
{{- end -}}
{{- get $out "value" -}}
{{- end -}}

{{- define "heteronetwork.validateCidrContainedBySourceRanges" -}}
{{- $value := printf "%v" .value -}}
{{- $path := .path -}}
{{- $sourcePath := .sourcePath -}}
{{- $sourceRanges := .sourceRanges -}}
{{- if and $sourceRanges (regexMatch "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+$" $value) -}}
{{- $bounds := splitList ":" (include "heteronetwork.ipv4CidrRange" (dict "value" $value)) -}}
{{- $start := int (index $bounds 0) -}}
{{- $end := int (index $bounds 1) -}}
{{- $contained := dict "ok" false -}}
{{- range $source := $sourceRanges -}}
{{- $sourceValue := printf "%v" $source -}}
{{- include "heteronetwork.validateCidr" (dict "path" $sourcePath "value" $sourceValue) -}}
{{- if regexMatch "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+$" $sourceValue -}}
{{- $sourceBounds := splitList ":" (include "heteronetwork.ipv4CidrRange" (dict "value" $sourceValue)) -}}
{{- $sourceStart := int (index $sourceBounds 0) -}}
{{- $sourceEnd := int (index $sourceBounds 1) -}}
{{- if and (le $sourceStart $start) (le $end $sourceEnd) -}}
{{- $_ := set $contained "ok" true -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if not (get $contained "ok") -}}
{{- fail (printf "%s entry %q must be contained by one of %s values because NetworkPolicy must not allow sources broader than the LoadBalancer source ranges" $path $value $sourcePath) -}}
{{- end -}}
{{- else if and $sourceRanges (contains ":" $value) -}}
{{- $parts := splitList "/" $value -}}
{{- $prefix := int (index $parts 1) -}}
{{- $bits := include "heteronetwork.ipv6CidrBits" (dict "path" $path "value" $value) -}}
{{- $contained := dict "ok" false -}}
{{- range $source := $sourceRanges -}}
{{- $sourceValue := printf "%v" $source -}}
{{- include "heteronetwork.validateCidr" (dict "path" $sourcePath "value" $sourceValue) -}}
{{- if contains ":" $sourceValue -}}
{{- $sourceParts := splitList "/" $sourceValue -}}
{{- $sourcePrefix := int (index $sourceParts 1) -}}
{{- if le $sourcePrefix $prefix -}}
{{- $sourceBits := include "heteronetwork.ipv6CidrBits" (dict "path" $sourcePath "value" $sourceValue) -}}
{{- if eq (substr 0 $sourcePrefix $bits) (substr 0 $sourcePrefix $sourceBits) -}}
{{- $_ := set $contained "ok" true -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if not (get $contained "ok") -}}
{{- fail (printf "%s entry %q must be contained by one of %s values because NetworkPolicy must not allow sources broader than the LoadBalancer source ranges" $path $value $sourcePath) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "heteronetwork.validateKubernetesRouteCidr" -}}
{{- $value := printf "%v" .value -}}
{{- $path := .path -}}
{{- include "heteronetwork.validateRestrictedCidr" (dict "path" $path "value" $value) -}}
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

{{- define "heteronetwork.validateIPAddress" -}}
{{- $value := .value -}}
{{- $path := .path -}}
{{- $ipv4Octet := "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])" -}}
{{- $ipv4 := regexMatch (printf "^%s\\.%s\\.%s\\.%s$" $ipv4Octet $ipv4Octet $ipv4Octet $ipv4Octet) $value -}}
{{- $ipv6 := and (contains ":" $value) (regexMatch "^[0-9A-Fa-f:.]+$" $value) -}}
{{- if not (or $ipv4 $ipv6) -}}
{{- fail (printf "%s value %q must be an IPv4 or IPv6 address" $path $value) -}}
{{- end -}}
{{- end -}}

{{- define "heteronetwork.validateUsableServiceIPAddress" -}}
{{- $value := printf "%v" .value -}}
{{- $path := .path -}}
{{- include "heteronetwork.validateIPAddress" (dict "path" $path "value" $value) -}}
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

{{- define "heteronetwork.validateExternalServiceIPAddress" -}}
{{- include "heteronetwork.validateUsableServiceIPAddress" . -}}
{{- end -}}

{{- define "heteronetwork.validateBoolean" -}}
{{- $path := .path -}}
{{- if not (kindIs "bool" .value) -}}
{{- fail (printf "%s must be true or false" $path) -}}
{{- end -}}
{{- end -}}

{{- define "heteronetwork.validateOptionalBoolean" -}}
{{- $path := .path -}}
{{- if and (not (kindIs "bool" .value)) (ne (printf "%v" .value) "") -}}
{{- fail (printf "%s must be true, false, or empty" $path) -}}
{{- end -}}
{{- end -}}

{{- define "heteronetwork.validateHttpEndpointURL" -}}
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

{{- define "heteronetwork.validateAdvertisedHttpEndpointURL" -}}
{{- include "heteronetwork.validateHttpEndpointURL" . -}}
{{- $value := printf "%v" .value -}}
{{- $path := .path -}}
{{- $authorityWithScheme := regexFind "^https?://[^/[:space:]?#]+" $value -}}
{{- $authority := trimPrefix "https://" (trimPrefix "http://" $authorityWithScheme) -}}
{{- if hasPrefix "[" $authority -}}
{{- $host := trimSuffix "]" (trimPrefix "[" (regexFind "^\\[[^\\]]+\\]" $authority)) -}}
{{- include "heteronetwork.validateUsableServiceIPAddress" (dict "path" (printf "%s host" $path) "value" $host) -}}
{{- else -}}
{{- $host := regexFind "^[^:]+" $authority -}}
{{- $ipv4Octet := "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])" -}}
{{- if regexMatch (printf "^%s\\.%s\\.%s\\.%s$" $ipv4Octet $ipv4Octet $ipv4Octet $ipv4Octet) $host -}}
{{- include "heteronetwork.validateUsableServiceIPAddress" (dict "path" (printf "%s host" $path) "value" $host) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "heteronetwork.validateSocketAddress" -}}
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

{{- define "heteronetwork.validateAdvertisedSocketAddress" -}}
{{- include "heteronetwork.validateSocketAddress" . -}}
{{- $value := printf "%v" .value -}}
{{- $path := .path -}}
{{- if hasPrefix "[" $value -}}
{{- $host := trimSuffix "]" (trimPrefix "[" (regexFind "^\\[[^\\]]+\\]" $value)) -}}
{{- include "heteronetwork.validateUsableServiceIPAddress" (dict "path" (printf "%s host" $path) "value" $host) -}}
{{- else -}}
{{- $host := regexFind "^[^:]+" $value -}}
{{- include "heteronetwork.validateUsableServiceIPAddress" (dict "path" (printf "%s host" $path) "value" $host) -}}
{{- end -}}
{{- end -}}

{{- define "heteronetwork.validateBindSocketAddress" -}}
{{- $value := printf "%v" .value -}}
{{- $path := .path -}}
{{- $allowPortZero := default false .allowPortZero -}}
{{- $ipv4Octet := "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])" -}}
{{- $ipv4Socket := regexMatch (printf "^%s\\.%s\\.%s\\.%s:[0-9]+$" $ipv4Octet $ipv4Octet $ipv4Octet $ipv4Octet) $value -}}
{{- $ipv6Socket := regexMatch "^\\[[0-9A-Fa-f:.]+\\]:[0-9]+$" $value -}}
{{- if not (or $ipv4Socket $ipv6Socket) -}}
{{- fail (printf "%s value %q must be an IPv4 host:port or [IPv6]:port bind socket address" $path $value) -}}
{{- end -}}
{{- $port := int (regexFind "[0-9]+$" $value) -}}
{{- if or (and (not $allowPortZero) (lt $port 1)) (gt $port 65535) -}}
{{- if $allowPortZero -}}
{{- fail (printf "%s port must be between 0 and 65535" $path) -}}
{{- else -}}
{{- fail (printf "%s port must be between 1 and 65535" $path) -}}
{{- end -}}
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

{{- define "heteronetwork.validateLabelKey" -}}
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

{{- define "heteronetwork.validateLabelValue" -}}
{{- $value := .value -}}
{{- $path := .path -}}
{{- if or (gt (len $value) 63) (and (ne $value "") (not (regexMatch "^[A-Za-z0-9]([A-Za-z0-9_.-]*[A-Za-z0-9])?$" $value))) -}}
{{- fail (printf "%s label value %q must be empty or a Kubernetes label value of at most 63 bytes" $path $value) -}}
{{- end -}}
{{- end -}}

{{- define "heteronetwork.validateNodeSelectorExpression" -}}
{{- $path := .path -}}
{{- $expression := .expression -}}
{{- if not (kindIs "map" $expression) -}}
{{- fail (printf "%s must be an object" $path) -}}
{{- end -}}
{{- range $field, $_ := $expression -}}
{{- if not (has $field (list "key" "operator" "values")) -}}
{{- fail (printf "%s has unsupported field %s" $path $field) -}}
{{- end -}}
{{- end -}}
{{- $key := default "" $expression.key -}}
{{- if eq $key "" -}}
{{- fail (printf "%s.key is required" $path) -}}
{{- end -}}
{{- include "heteronetwork.validateLabelKey" (dict "path" $path "key" $key) -}}
{{- $operator := default "" $expression.operator -}}
{{- if not (has $operator (list "In" "NotIn" "Exists" "DoesNotExist" "Gt" "Lt")) -}}
{{- fail (printf "%s.operator must be In, NotIn, Exists, DoesNotExist, Gt, or Lt" $path) -}}
{{- end -}}
{{- $values := list -}}
{{- if hasKey $expression "values" -}}
{{- if not (kindIs "slice" $expression.values) -}}
{{- fail (printf "%s.values must be a list" $path) -}}
{{- end -}}
{{- $values = $expression.values -}}
{{- end -}}
{{- if or (eq $operator "In") (eq $operator "NotIn") -}}
{{- if not $values -}}
{{- fail (printf "%s.values is required when operator is %s" $path $operator) -}}
{{- end -}}
{{- range $value := $values -}}
{{- include "heteronetwork.validateLabelValue" (dict "path" (printf "%s.values" $path) "value" (printf "%v" $value)) -}}
{{- end -}}
{{- else if or (eq $operator "Exists") (eq $operator "DoesNotExist") -}}
{{- if $values -}}
{{- fail (printf "%s.values must be omitted when operator is %s" $path $operator) -}}
{{- end -}}
{{- else -}}
{{- if ne (len $values) 1 -}}
{{- fail (printf "%s.values must contain exactly one integer when operator is %s" $path $operator) -}}
{{- end -}}
{{- $value := printf "%v" (index $values 0) -}}
{{- if not (regexMatch "^-?([0-9]|[1-9][0-9]*)$" $value) -}}
{{- fail (printf "%s.values entry %q must be an integer when operator is %s" $path $value $operator) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "heteronetwork.validateLabelSelectorExpression" -}}
{{- $path := .path -}}
{{- $expression := .expression -}}
{{- if not (kindIs "map" $expression) -}}
{{- fail (printf "%s must be an object" $path) -}}
{{- end -}}
{{- range $field, $_ := $expression -}}
{{- if not (has $field (list "key" "operator" "values")) -}}
{{- fail (printf "%s has unsupported field %s" $path $field) -}}
{{- end -}}
{{- end -}}
{{- $key := default "" $expression.key -}}
{{- if eq $key "" -}}
{{- fail (printf "%s.key is required" $path) -}}
{{- end -}}
{{- include "heteronetwork.validateLabelKey" (dict "path" $path "key" $key) -}}
{{- $operator := default "" $expression.operator -}}
{{- if not (has $operator (list "In" "NotIn" "Exists" "DoesNotExist")) -}}
{{- fail (printf "%s.operator must be In, NotIn, Exists, or DoesNotExist" $path) -}}
{{- end -}}
{{- $values := list -}}
{{- if hasKey $expression "values" -}}
{{- if not (kindIs "slice" $expression.values) -}}
{{- fail (printf "%s.values must be a list" $path) -}}
{{- end -}}
{{- $values = $expression.values -}}
{{- end -}}
{{- if or (eq $operator "In") (eq $operator "NotIn") -}}
{{- if not $values -}}
{{- fail (printf "%s.values is required when operator is %s" $path $operator) -}}
{{- end -}}
{{- range $value := $values -}}
{{- include "heteronetwork.validateLabelValue" (dict "path" (printf "%s.values" $path) "value" (printf "%v" $value)) -}}
{{- end -}}
{{- else -}}
{{- if $values -}}
{{- fail (printf "%s.values must be omitted when operator is %s" $path $operator) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "heteronetwork.validatePodAffinityTerm" -}}
{{- $path := .path -}}
{{- $term := .term -}}
{{- if not (kindIs "map" $term) -}}
{{- fail (printf "%s must be an object" $path) -}}
{{- end -}}
{{- range $field, $_ := $term -}}
{{- if not (has $field (list "topologyKey" "namespaces" "matchExpressions")) -}}
{{- fail (printf "%s has unsupported field %s" $path $field) -}}
{{- end -}}
{{- end -}}
{{- $topologyKey := default "" $term.topologyKey -}}
{{- if eq $topologyKey "" -}}
{{- fail (printf "%s.topologyKey is required" $path) -}}
{{- end -}}
{{- include "heteronetwork.validateLabelKey" (dict "path" $path "key" $topologyKey) -}}
{{- if not (hasKey $term "matchExpressions") -}}
{{- fail (printf "%s.matchExpressions is required" $path) -}}
{{- end -}}
{{- if not (kindIs "slice" $term.matchExpressions) -}}
{{- fail (printf "%s.matchExpressions must be a list" $path) -}}
{{- end -}}
{{- if not $term.matchExpressions -}}
{{- fail (printf "%s.matchExpressions must not be empty" $path) -}}
{{- end -}}
{{- range $expressionIndex, $expression := $term.matchExpressions -}}
{{- include "heteronetwork.validateLabelSelectorExpression" (dict "path" (printf "%s.matchExpressions[%d]" $path $expressionIndex) "expression" $expression) -}}
{{- end -}}
{{- if hasKey $term "namespaces" -}}
{{- if not (kindIs "slice" $term.namespaces) -}}
{{- fail (printf "%s.namespaces must be a list" $path) -}}
{{- end -}}
{{- $namespaces := dict -}}
{{- range $namespaceIndex, $namespace := $term.namespaces -}}
{{- $namespaceValue := printf "%v" $namespace -}}
{{- include "heteronetwork.validateDnsLabelWithMax" (dict "path" (printf "%s.namespaces[%d]" $path $namespaceIndex) "value" $namespaceValue "maxBytes" 63) -}}
{{- if hasKey $namespaces $namespaceValue -}}
{{- fail (printf "%s.namespaces entry %q must not be repeated" $path $namespaceValue) -}}
{{- end -}}
{{- $_ := set $namespaces $namespaceValue true -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "heteronetwork.validateResourceQuantity" -}}
{{- $value := .value -}}
{{- $path := .path -}}
{{- if and (ne $value "") (or (gt (len $value) 64) (not (regexMatch "^[0-9]([0-9A-Za-z.+-]*[0-9A-Za-z])?$" $value))) -}}
{{- fail (printf "%s resource quantity %q must be a non-negative Kubernetes quantity without whitespace" $path $value) -}}
{{- end -}}
{{- end -}}

{{- define "heteronetwork.validateNonNegativeInteger" -}}
{{- $value := .value -}}
{{- $path := .path -}}
{{- if and (ne $value "") (not (regexMatch "^([0-9]|[1-9][0-9]*)$" $value)) -}}
{{- fail (printf "%s %q must be a non-negative integer" $path $value) -}}
{{- end -}}
{{- end -}}

{{- define "heteronetwork.validateNonNegativeIntegerMax" -}}
{{- $value := .value -}}
{{- $path := .path -}}
{{- $max := printf "%v" .max -}}
{{- if eq $value "" -}}
{{- fail (printf "%s must be a non-negative integer" $path) -}}
{{- end -}}
{{- include "heteronetwork.validateOptionalNonNegativeIntegerMax" . -}}
{{- end -}}

{{- define "heteronetwork.validateOptionalNonNegativeIntegerMax" -}}
{{- $value := .value -}}
{{- $path := .path -}}
{{- $max := printf "%v" .max -}}
{{- include "heteronetwork.validateNonNegativeInteger" . -}}
{{- if or (gt (len $value) (len $max)) (and (eq (len $value) (len $max)) (gt $value $max)) -}}
{{- fail (printf "%s must be a non-negative integer no greater than %s" $path $max) -}}
{{- end -}}
{{- end -}}

{{- define "heteronetwork.validateNonNegativeInt64" -}}
{{- $value := .value -}}
{{- $path := .path -}}
{{- include "heteronetwork.validateNonNegativeInteger" . -}}
{{- if and (ne $value "") (or (gt (len $value) 19) (and (eq (len $value) 19) (gt $value "9223372036854775807"))) -}}
{{- fail (printf "%s %q must be a non-negative int64" $path $value) -}}
{{- end -}}
{{- end -}}

{{- define "heteronetwork.validateIntOrPercent" -}}
{{- $value := .value -}}
{{- $path := .path -}}
{{- if and (ne $value "") (not (regexMatch "^([0-9]|[1-9][0-9]*|[0-9]%|[1-9][0-9]%|100%)$" $value)) -}}
{{- fail (printf "%s %q must be a non-negative integer or percentage from 0%% to 100%%" $path $value) -}}
{{- end -}}
{{- if and (ne $value "") (not (regexMatch "%$" $value)) (or (gt (len $value) 10) (and (eq (len $value) 10) (gt $value "2147483647"))) -}}
{{- fail (printf "%s %q must be a non-negative IntOrString integer no greater than 2147483647" $path $value) -}}
{{- end -}}
{{- end -}}

{{- define "heteronetwork.validateAnnotationKey" -}}
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

{{- define "heteronetwork.validateServiceAnnotationKey" -}}
{{- include "heteronetwork.validateAnnotationKey" . -}}
{{- $key := lower (printf "%v" .key) -}}
{{- $path := .path -}}
{{- if or (contains "source-range" $key) (contains "inbound-cidr" $key) -}}
{{- fail (printf "%s annotation key %q must not configure LoadBalancer source ranges; use loadBalancerSourceRanges values instead" $path .key) -}}
{{- else if or (contains "load-balancer-ip" $key) (contains "loadbalancerip" $key) (contains "load-balancer-eip" $key) (contains "eip-allocations" $key) (hasSuffix "/load-balancer-address" $key) (hasSuffix "/loadbalancer-address" $key) (contains "static-ip" $key) (contains "ip-address" $key) (contains "private-ipv4-address" $key) (contains "pip-name" $key) (contains "pip-prefix" $key) (contains "public-ip-prefix" $key) (contains "public-ips" $key) (contains "lb-ipam-ips" $key) -}}
{{- fail (printf "%s annotation key %q must not configure LoadBalancer fixed addresses; use loadBalancerIP or externalIPs values instead" $path .key) -}}
{{- else if or (contains "proxy-protocol" $key) (contains "proxyprotocol" $key) -}}
{{- fail (printf "%s annotation key %q must not enable PROXY protocol; HeteroNetwork Services do not accept PROXY protocol headers" $path .key) -}}
{{- else if or (contains "healthcheck" $key) (contains "health-check" $key) (contains "health_probe" $key) (contains "health-probe" $key) -}}
{{- fail (printf "%s annotation key %q must not configure LoadBalancer health checks; use typed Service health-check controls instead" $path .key) -}}
{{- else if or (contains "ssl-cert" $key) (contains "ssl-ports" $key) (contains "ssl-negotiation-policy" $key) (contains "tls-cert" $key) (contains "tls-ports" $key) (contains "certificate-arn" $key) (contains "certificate" $key) (contains "load-balancer-protocol" $key) (contains "loadbalancer-protocol" $key) (contains "backend-protocol" $key) (contains "backend-protocol-version" $key) (contains "app-protocol" $key) (contains "app_protocol" $key) (contains "http2-ports" $key) (contains "http3-ports" $key) (contains "redirect-http" $key) (contains "listener" $key) (contains "alpn-policy" $key) (contains "high-availability-ports" $key) (contains "ha-ports" $key) (contains "enable-icmp" $key) -}}
{{- fail (printf "%s annotation key %q must not configure LoadBalancer TLS, listeners, or backend protocols; use typed Service ports/appProtocol and plain HeteroNetwork listeners instead" $path .key) -}}
{{- else if or (contains "load-balancer-scheme" $key) (contains "loadbalancer-scheme" $key) (contains "load-balancer-internal" $key) (contains "loadbalancer-internal" $key) (contains "internal-load-balancer" $key) (contains "load-balancer-type" $key) (contains "loadbalancer-type" $key) (contains "load-balancer-address-type" $key) (contains "loadbalancer-address-type" $key) (contains "load-balancer-class" $key) (contains "loadbalancerclass" $key) (contains "load-balancer-shape" $key) (contains "loadbalancer-shape" $key) (contains "load-balancer-cloud-provider-ip-type" $key) (contains "nlb-target-type" $key) (contains "l4-rbs" $key) (contains "global-access" $key) (contains "allow-global-access" $key) -}}
{{- fail (printf "%s annotation key %q must not configure LoadBalancer scope or implementation type; use typed Service type, loadBalancerClass, exposure acknowledgement, and source-range controls instead" $path .key) -}}
{{- else if or (contains "security-group" $key) (contains "securitygroup" $key) (contains "firewall" $key) (contains "waf" $key) (contains "web-acl" $key) (contains "webacl" $key) (contains "security-policy" $key) (contains "securitypolicy" $key) (contains "security-list" $key) (contains "allowed-service-tags" $key) (contains "allowed-ip-ranges" $key) (contains "shared-securityrule" $key) -}}
{{- fail (printf "%s annotation key %q must not configure LoadBalancer firewall or security groups; use loadBalancerSourceRanges or NetworkPolicy values instead" $path .key) -}}
{{- else if or (contains "subnet" $key) (contains "vlan" $key) (contains "network-tier" $key) (contains "network-endpoint-group" $key) (contains "cloud.google.com/neg" $key) (contains "resource-group" $key) (contains "availability-zone" $key) (contains "cloud-provider-zone" $key) -}}
{{- fail (printf "%s annotation key %q must not configure LoadBalancer network placement; use typed Service type, loadBalancerClass, source-range, and exposure controls instead" $path .key) -}}
{{- else if or (contains "load-balancer-attributes" $key) (contains "loadbalancer-attributes" $key) (contains "backend-config" $key) (contains "target-group-attributes" $key) (contains "targetgroup-attributes" $key) (contains "access-log" $key) (contains "accesslog" $key) (contains "enable-features" $key) (contains "idle-timeout" $key) (contains "connection-draining" $key) (contains "deregistration-delay" $key) (contains "cross-zone" $key) (contains "preserve-client-ip" $key) (contains "tcp-reset" $key) (contains "size-unit" $key) (contains "flavor-id" $key) -}}
{{- fail (printf "%s annotation key %q must not configure LoadBalancer operational attributes; use typed Service traffic policy, appProtocol, and HeteroNetwork listener controls instead" $path .key) -}}
{{- else if or (contains "external-dns" $key) (contains "dns-name" $key) (contains "dns-label" $key) (contains "dns-record" $key) (contains "load-balancer-hostname" $key) (contains "loadbalancer-hostname" $key) (contains "domain-name" $key) (contains "domainname" $key) (contains "fqdn" $key) -}}
{{- fail (printf "%s annotation key %q must not publish LoadBalancer DNS names; use relayAdvertisement values and explicit Service exposure controls instead" $path .key) -}}
{{- else if or (contains "load-balancer-name" $key) (contains "loadbalancer-name" $key) (contains "target-group-name" $key) (contains "targetgroup-name" $key) (contains "load-balancer-configuration" $key) (contains "load-balancer-mode" $key) (contains "resource-tags" $key) (contains "additional-resource-tags" $key) (contains "defined-tags" $key) (contains "freeform-tags" $key) (contains "pip-ip-tags" $key) (contains "pip-tags" $key) (contains "address-pool" $key) (contains "addresspool" $key) (contains "ip-pool" $key) (contains "ippool" $key) -}}
{{- fail (printf "%s annotation key %q must not configure LoadBalancer resource identity, tags, or address pools; use typed Service exposure controls and explicit fixed-address values instead" $path .key) -}}
{{- else if or (contains "azure-pls" $key) (contains "private-link" $key) (contains "privatelink" $key) (contains "private-service-connect" $key) (contains "endpoint-service" $key) (contains "service-attachment" $key) -}}
{{- fail (printf "%s annotation key %q must not configure LoadBalancer Private Link or endpoint-service publishing; use typed Service exposure controls and relayAdvertisement values instead" $path .key) -}}
{{- else if or (contains "target-node-label" $key) (contains "target-node-selector" $key) (contains "backend-node-label" $key) (contains "backend-node-selector" $key) (contains "node-selector" $key) (contains "node-labels" $key) -}}
{{- fail (printf "%s annotation key %q must not configure LoadBalancer backend target selection; use DaemonSet scheduling, externalTrafficPolicy values, and typed Service exposure controls instead" $path .key) -}}
{{- else if or (contains "source-nat" $key) (contains "disable-load-balancer-snat" $key) (contains "disable-snat" $key) (contains "outbound-snat" $key) (contains "enable-prefix-for-ipv6-source-nat" $key) -}}
{{- fail (printf "%s annotation key %q must not configure LoadBalancer source NAT behavior; use internal/externalTrafficPolicy, source ranges, and NetworkPolicy values instead" $path .key) -}}
{{- else if or (contains "traffic-distribution" $key) (contains "traffic_distribution" $key) (contains "weighted-load-balancing" $key) (contains "load-balancing-policy" $key) (contains "loadbalancing-policy" $key) (contains "load-balancer-policy" $key) (contains "loadbalancer-policy" $key) (contains "load-balancing-algorithm" $key) (contains "traffic-policy" $key) (contains "traffic_policy" $key) (contains "topology-mode" $key) (contains "topology-aware" $key) -}}
{{- fail (printf "%s annotation key %q must not configure LoadBalancer traffic distribution; use internal/externalTrafficPolicy and trafficDistribution values instead" $path .key) -}}
{{- end -}}
{{- end -}}

{{- define "heteronetwork.validateAnnotationValue" -}}
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

{{- define "heteronetwork.validateOptionalQualifiedNameWithPrefix" -}}
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
