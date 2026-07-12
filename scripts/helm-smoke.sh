#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
helm_image="${IPARS_HELM_IMAGE:-alpine/helm:3.14.4}"

helm_cmd() {
  tar -C "$repo_root" -cf - charts/ipars | docker run --rm -i --entrypoint sh "$helm_image" -c '
set -eu
mkdir -p /work
tar -C /work -xf -
helm "$@"
' sh "$@"
}

template_ok() {
  local name="$1"
  shift
  helm_cmd template ipars /work/charts/ipars "$@" >/tmp/"ipars-helm-${name}.yaml"
}

template_release_ok() {
  local name="$1"
  local release="$2"
  shift 2
  helm_cmd template "$release" /work/charts/ipars "$@" >/tmp/"ipars-helm-${name}.yaml"
}

template_fails() {
  local name="$1"
  local expected="$2"
  shift 2
  local stderr="/tmp/ipars-helm-${name}.stderr"
  if helm_cmd template ipars /work/charts/ipars "$@" >/tmp/"ipars-helm-${name}.yaml" 2>"$stderr"; then
    echo "expected Helm template failure for ${name}" >&2
    exit 1
  fi
  if ! grep -Fq "$expected" "$stderr"; then
    echo "Helm template failure for ${name} did not include expected message" >&2
    cat "$stderr" >&2
    exit 1
  fi
}

assert_rendered_contains() {
  local name="$1"
  local expected="$2"
  local rendered="/tmp/ipars-helm-${name}.yaml"
  if ! grep -Fq -- "$expected" "$rendered"; then
    echo "Helm template output for ${name} did not include expected content: ${expected}" >&2
    cat "$rendered" >&2
    exit 1
  fi
}

assert_rendered_absent() {
  local name="$1"
  local unexpected="$2"
  local rendered="/tmp/ipars-helm-${name}.yaml"
  if grep -Fq -- "$unexpected" "$rendered"; then
    echo "Helm template output for ${name} unexpectedly included content: ${unexpected}" >&2
    cat "$rendered" >&2
    exit 1
  fi
}

helm_cmd lint /work/charts/ipars >/tmp/ipars-helm-lint.txt

template_ok default

assert_rendered_contains default "mountPath: /dev/net/tun"
assert_rendered_contains default "- --wireguard-listen-port"
assert_rendered_contains default '- "51820"'
assert_rendered_contains default "- --stun-bind"
assert_rendered_contains default '- "0.0.0.0:51820"'
assert_rendered_contains default "name: IPARS_AGENT_API_BEARER_TOKEN"
assert_rendered_contains default 'key: "agent-api-token"'

template_fails agent-api-token-key-empty \
  "agent.apiBearerTokenSecretKey must contain only ASCII letters" \
  --set-string agent.apiBearerTokenSecretKey=

template_fails agent-api-token-key-reuses-join-key \
  "agent.apiBearerTokenSecretKey must differ from agent.joinTokenSecretKey" \
  --set-string agent.apiBearerTokenSecretKey=token

template_ok agent-listen-port \
  --set agent.wireguardListenPort=51830 \
  --set-string agent.stunBind=0.0.0.0:51830

assert_rendered_contains agent-listen-port "- --wireguard-listen-port"
assert_rendered_contains agent-listen-port '- "51830"'
assert_rendered_contains agent-listen-port "- --stun-bind"
assert_rendered_contains agent-listen-port '- "0.0.0.0:51830"'

template_fails agent-listen-port-zero \
  "agent.wireguardListenPort must be between 1 and 65535" \
  --set agent.wireguardListenPort=0

template_fails agent-listen-port-mismatch \
  "agent.stunBind port must equal agent.wireguardListenPort" \
  --set agent.wireguardListenPort=51820 \
  --set-string agent.stunBind=0.0.0.0:51821

template_ok agent-runtime-dry-run \
  --set-string agent.runtimeBackend=dry-run

assert_rendered_contains agent-runtime-dry-run "- --runtime-backend"
assert_rendered_contains agent-runtime-dry-run '- "dry-run"'
assert_rendered_absent agent-runtime-dry-run "mountPath: /dev/net/tun"
assert_rendered_absent agent-runtime-dry-run "name: dev-net-tun"

template_fails agent-runtime-invalid \
  "agent.runtimeBackend must be linux-command or dry-run" \
  --set-string agent.runtimeBackend=invalid

template_ok agent-http-timeouts \
  --set agent.http.connectTimeoutSeconds=7 \
  --set agent.http.requestTimeoutSeconds=45

assert_rendered_contains agent-http-timeouts "- --http-connect-timeout-seconds"
assert_rendered_contains agent-http-timeouts '- "7"'
assert_rendered_contains agent-http-timeouts "- --http-request-timeout-seconds"
assert_rendered_contains agent-http-timeouts '- "45"'

template_fails agent-http-connect-timeout-zero \
  "agent.http.connectTimeoutSeconds must be greater than zero" \
  --set agent.http.connectTimeoutSeconds=0

template_fails agent-http-request-timeout-oversized \
  "agent.http.requestTimeoutSeconds must be a non-negative integer no greater than 3600" \
  --set agent.http.requestTimeoutSeconds=3601

template_fails agent-http-timeout-order \
  "agent.http.connectTimeoutSeconds must not exceed agent.http.requestTimeoutSeconds" \
  --set agent.http.connectTimeoutSeconds=31 \
  --set agent.http.requestTimeoutSeconds=30

template_ok cluster-endpoints \
  --set-string cluster.controlPlaneUrl=https://control.example.com:8443 \
  --set-string cluster.signalUrl=https://signal.example.com:9443 \
  --set-string cluster.stunEndpoint=203.0.113.53:3478

assert_rendered_contains cluster-endpoints "- --control-plane-url"
assert_rendered_contains cluster-endpoints '"https://control.example.com:8443"'
assert_rendered_contains cluster-endpoints "- --signal-url"
assert_rendered_contains cluster-endpoints '"https://signal.example.com:9443"'
assert_rendered_contains cluster-endpoints "- --stun-server"
assert_rendered_contains cluster-endpoints '"203.0.113.53:3478"'
assert_rendered_contains cluster-endpoints "name: IPARS_CONTROL_PLANE_URL"
assert_rendered_contains cluster-endpoints "name: IPARS_SIGNAL_URL"
assert_rendered_contains cluster-endpoints "name: IPARS_STUN_ENDPOINT"

template_release_ok release-scoping edge \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=ClusterIP \
  --set agent.podDisruptionBudget.enabled=true \
  --set agent.podDisruptionBudget.maxUnavailable=1 \
  --set networkPolicy.enabled=true \
  --set networkPolicy.acknowledgeHostNetwork=true \
  --set networkPolicy.agentApi.enabled=true \
  --set-string 'networkPolicy.agentApi.allowedCidrs[0]=10.0.0.0/8'

assert_rendered_contains release-scoping "name: edge-ipars"
assert_rendered_contains release-scoping "name: edge-ipars-agent"
assert_rendered_contains release-scoping "name: edge-ipars-agent-api"
assert_rendered_contains release-scoping 'app.kubernetes.io/instance: "edge"'
assert_rendered_absent release-scoping "name: ipars-agent"

template_release_ok name-overrides edge \
  --set-string nameOverride=agent \
  --set-string fullnameOverride=fixed-ipars \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=ClusterIP

assert_rendered_contains name-overrides "name: fixed-ipars"
assert_rendered_contains name-overrides "name: fixed-ipars-agent"
assert_rendered_absent name-overrides "name: edge-ipars"

template_ok pod-runtime \
  --set-string agent.schedulerName=ipars-scheduler \
  --set-string agent.runtimeClassName=ipars-runtime

assert_rendered_contains pod-runtime 'schedulerName: "ipars-scheduler"'
assert_rendered_contains pod-runtime 'runtimeClassName: "ipars-runtime"'

template_ok pod-security-context \
  --set agent.podSecurityContext.runAsUser=1000 \
  --set agent.podSecurityContext.runAsGroup=1000 \
  --set agent.podSecurityContext.runAsNonRoot=true \
  --set agent.podSecurityContext.fsGroup=2000 \
  --set-string agent.podSecurityContext.fsGroupChangePolicy=OnRootMismatch \
  --set 'agent.podSecurityContext.supplementalGroups[0]=2001' \
  --set 'agent.podSecurityContext.supplementalGroups[1]=2002'

assert_rendered_contains pod-security-context "securityContext:"
assert_rendered_contains pod-security-context "runAsUser: 1000"
assert_rendered_contains pod-security-context "runAsGroup: 1000"
assert_rendered_contains pod-security-context "runAsNonRoot: true"
assert_rendered_contains pod-security-context "fsGroup: 2000"
assert_rendered_contains pod-security-context 'fsGroupChangePolicy: "OnRootMismatch"'
assert_rendered_contains pod-security-context "supplementalGroups:"
assert_rendered_contains pod-security-context "- 2001"
assert_rendered_contains pod-security-context "- 2002"

template_ok pod-health-probes \
  --set-string agent.probes.liveness.path=/livez \
  --set agent.probes.liveness.periodSeconds=20 \
  --set-string agent.probes.readiness.path=/readyz \
  --set agent.probes.readiness.failureThreshold=2 \
  --set-string agent.probes.startup.path=/startupz \
  --set agent.probes.startup.initialDelaySeconds=0 \
  --set agent.probes.startup.periodSeconds=5 \
  --set agent.probes.startup.failureThreshold=30

assert_rendered_contains pod-health-probes "livenessProbe:"
assert_rendered_contains pod-health-probes 'path: "/livez"'
assert_rendered_contains pod-health-probes "periodSeconds: 20"
assert_rendered_contains pod-health-probes "readinessProbe:"
assert_rendered_contains pod-health-probes 'path: "/readyz"'
assert_rendered_contains pod-health-probes "failureThreshold: 2"
assert_rendered_contains pod-health-probes "startupProbe:"
assert_rendered_contains pod-health-probes 'path: "/startupz"'
assert_rendered_contains pod-health-probes "initialDelaySeconds: 0"
assert_rendered_contains pod-health-probes "failureThreshold: 30"

template_ok pod-lifecycle \
  --set agent.lifecycle.preStopSleepSeconds=20 \
  --set agent.terminationGracePeriodSeconds=60

assert_rendered_contains pod-lifecycle "lifecycle:"
assert_rendered_contains pod-lifecycle "preStop:"
assert_rendered_contains pod-lifecycle "command:"
assert_rendered_contains pod-lifecycle "- /bin/sh"
assert_rendered_contains pod-lifecycle "- -c"
assert_rendered_contains pod-lifecycle '- "sleep 20"'
assert_rendered_contains pod-lifecycle "terminationGracePeriodSeconds: 60"

template_fails pod-lifecycle-zero \
  "agent.lifecycle.preStopSleepSeconds must be greater than zero when set" \
  --set agent.lifecycle.preStopSleepSeconds=0

template_fails pod-startup-probe-string-enabled \
  "agent.probes.startup.enabled must be true or false" \
  --set-string agent.probes.startup.enabled=false

template_fails pod-startup-probe-zero-threshold \
  "agent.probes.startup.failureThreshold must be greater than zero" \
  --set agent.probes.startup.failureThreshold=0

template_fails pod-security-context-root-nonroot \
  "agent.podSecurityContext.runAsNonRoot=true cannot be used with runAsUser=0" \
  --set agent.podSecurityContext.runAsUser=0 \
  --set agent.podSecurityContext.runAsNonRoot=true

template_fails pod-security-context-fsgroup-policy-without-fsgroup \
  "agent.podSecurityContext.fsGroupChangePolicy requires agent.podSecurityContext.fsGroup" \
  --set-string agent.podSecurityContext.fsGroupChangePolicy=OnRootMismatch

template_fails pod-security-context-duplicate-supplemental-group \
  "agent.podSecurityContext.supplementalGroups entry 2001 must not be repeated" \
  --set 'agent.podSecurityContext.supplementalGroups[0]=2001' \
  --set 'agent.podSecurityContext.supplementalGroups[1]=2001'

template_ok node-affinity \
  --set-string 'agent.nodeAffinity.required.matchExpressions[0].key=node-role.kubernetes.io/worker' \
  --set-string 'agent.nodeAffinity.required.matchExpressions[0].operator=Exists' \
  --set 'agent.nodeAffinity.preferred[0].weight=75' \
  --set-string 'agent.nodeAffinity.preferred[0].matchExpressions[0].key=node.kubernetes.io/instance-type' \
  --set-string 'agent.nodeAffinity.preferred[0].matchExpressions[0].operator=In' \
  --set-string 'agent.nodeAffinity.preferred[0].matchExpressions[0].values[0]=m7i.large' \
  --set-string 'agent.nodeAffinity.preferred[0].matchExpressions[0].values[1]=m7i.xlarge'

assert_rendered_contains node-affinity "affinity:"
assert_rendered_contains node-affinity "nodeAffinity:"
assert_rendered_contains node-affinity "requiredDuringSchedulingIgnoredDuringExecution:"
assert_rendered_contains node-affinity 'key: "node-role.kubernetes.io/worker"'
assert_rendered_contains node-affinity 'operator: "Exists"'
assert_rendered_contains node-affinity "preferredDuringSchedulingIgnoredDuringExecution:"
assert_rendered_contains node-affinity "weight: 75"
assert_rendered_contains node-affinity 'key: "node.kubernetes.io/instance-type"'
assert_rendered_contains node-affinity 'operator: "In"'
assert_rendered_contains node-affinity '- "m7i.large"'

template_ok pod-affinity \
  --set-string 'agent.podAffinity.required[0].topologyKey=kubernetes.io/hostname' \
  --set-string 'agent.podAffinity.required[0].namespaces[0]=ipars-system' \
  --set-string 'agent.podAffinity.required[0].matchExpressions[0].key=app.kubernetes.io/name' \
  --set-string 'agent.podAffinity.required[0].matchExpressions[0].operator=In' \
  --set-string 'agent.podAffinity.required[0].matchExpressions[0].values[0]=ipars' \
  --set 'agent.podAntiAffinity.preferred[0].weight=90' \
  --set-string 'agent.podAntiAffinity.preferred[0].topologyKey=topology.kubernetes.io/zone' \
  --set-string 'agent.podAntiAffinity.preferred[0].matchExpressions[0].key=ipars.io/role' \
  --set-string 'agent.podAntiAffinity.preferred[0].matchExpressions[0].operator=Exists'

assert_rendered_contains pod-affinity "podAffinity:"
assert_rendered_contains pod-affinity "podAntiAffinity:"
assert_rendered_contains pod-affinity 'topologyKey: "kubernetes.io/hostname"'
assert_rendered_contains pod-affinity 'topologyKey: "topology.kubernetes.io/zone"'
assert_rendered_contains pod-affinity "namespaces:"
assert_rendered_contains pod-affinity '- "ipars-system"'
assert_rendered_contains pod-affinity 'key: "app.kubernetes.io/name"'
assert_rendered_contains pod-affinity 'operator: "In"'
assert_rendered_contains pod-affinity '- "ipars"'
assert_rendered_contains pod-affinity "podAffinityTerm:"
assert_rendered_contains pod-affinity "weight: 90"
assert_rendered_contains pod-affinity 'key: "ipars.io/role"'
assert_rendered_contains pod-affinity 'operator: "Exists"'

template_ok topology-spread \
  --set-string 'agent.topologySpreadConstraints[0].topologyKey=topology.kubernetes.io/zone' \
  --set 'agent.topologySpreadConstraints[0].maxSkew=1' \
  --set-string 'agent.topologySpreadConstraints[0].whenUnsatisfiable=DoNotSchedule' \
  --set 'agent.topologySpreadConstraints[0].minDomains=2' \
  --set-string 'agent.topologySpreadConstraints[0].nodeAffinityPolicy=Honor' \
  --set-string 'agent.topologySpreadConstraints[0].nodeTaintsPolicy=Ignore'

assert_rendered_contains topology-spread "topologySpreadConstraints:"
assert_rendered_contains topology-spread 'topologyKey: "topology.kubernetes.io/zone"'
assert_rendered_contains topology-spread 'whenUnsatisfiable: "DoNotSchedule"'
assert_rendered_contains topology-spread "minDomains: 2"
assert_rendered_contains topology-spread 'nodeAffinityPolicy: "Honor"'
assert_rendered_contains topology-spread 'nodeTaintsPolicy: "Ignore"'
assert_rendered_contains topology-spread "labelSelector:"
assert_rendered_contains topology-spread 'app.kubernetes.io/instance: "ipars"'

template_ok agent-api \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=ClusterIP

template_ok relay-service \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=ClusterIP

template_fails relay-advertisement-loopback-public-endpoint \
  "agent.relayAdvertisement.publicEndpoint host value \"127.0.0.1\" must not be a loopback address" \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=127.0.0.1:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580

template_fails relay-advertisement-link-local-admission-url \
  "agent.relayAdvertisement.admissionUrl host value \"169.254.169.254\" must not be a link-local address" \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://169.254.169.254:9580

template_ok service-traffic-controls \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=ClusterIP \
  --set agent.apiService.internalTrafficPolicy=Local \
  --set agent.apiService.trafficDistribution=PreferSameNode \
  --set agent.apiService.sessionAffinity=ClientIP \
  --set agent.apiService.sessionAffinityTimeoutSeconds=600 \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=ClusterIP \
  --set agent.relayService.internalTrafficPolicy=Cluster \
  --set agent.relayService.trafficDistribution=PreferClose \
  --set agent.relayService.sessionAffinity=ClientIP \
  --set agent.relayService.sessionAffinityTimeoutSeconds=900

assert_rendered_contains service-traffic-controls "internalTrafficPolicy: Local"
assert_rendered_contains service-traffic-controls "trafficDistribution: PreferSameNode"
assert_rendered_contains service-traffic-controls "timeoutSeconds: 600"
assert_rendered_contains service-traffic-controls "internalTrafficPolicy: Cluster"
assert_rendered_contains service-traffic-controls "trafficDistribution: PreferClose"
assert_rendered_contains service-traffic-controls "timeoutSeconds: 900"

template_ok cluster-external-traffic-policy \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=NodePort \
  --set agent.apiService.exposureAcknowledged=true \
  --set agent.apiService.externalTrafficPolicy=Cluster \
  --set agent.apiService.allowClusterExternalTrafficPolicy=true \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=NodePort \
  --set agent.relayService.exposureAcknowledged=true \
  --set agent.relayService.externalTrafficPolicy=Cluster \
  --set agent.relayService.allowClusterExternalTrafficPolicy=true

assert_rendered_contains cluster-external-traffic-policy "externalTrafficPolicy: Cluster"

template_ok load-balancer-source-ranges \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set-string 'agent.apiService.loadBalancerSourceRanges[0]=198.51.100.0/24' \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=LoadBalancer \
  --set agent.relayService.exposureAcknowledged=true \
  --set-string 'agent.relayService.loadBalancerSourceRanges[0]=203.0.113.0/24'

assert_rendered_contains load-balancer-source-ranges "type: LoadBalancer"
assert_rendered_contains load-balancer-source-ranges "loadBalancerSourceRanges:"
assert_rendered_contains load-balancer-source-ranges "198.51.100.0/24"
assert_rendered_contains load-balancer-source-ranges "203.0.113.0/24"

template_fails load-balancer-ipv6-source-range-noncanonical \
  "agent.apiService.loadBalancerSourceRanges entry \"2001:db8:10::1/48\" must be a canonical IPv6 CIDR" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set-string 'agent.apiService.loadBalancerSourceRanges[0]=2001:db8:10::1/48'

template_ok unrestricted-load-balancer \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set agent.apiService.allowUnrestrictedLoadBalancer=true \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=LoadBalancer \
  --set agent.relayService.exposureAcknowledged=true \
  --set agent.relayService.allowUnrestrictedLoadBalancer=true

assert_rendered_contains unrestricted-load-balancer "type: LoadBalancer"
assert_rendered_absent unrestricted-load-balancer "loadBalancerSourceRanges:"

template_ok network-policy \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=ClusterIP \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=ClusterIP \
  --set networkPolicy.enabled=true \
  --set networkPolicy.acknowledgeHostNetwork=true \
  --set networkPolicy.agentApi.enabled=true \
  --set-string 'networkPolicy.agentApi.allowedCidrs[0]=10.0.0.0/8' \
  --set networkPolicy.relay.enabled=true \
  --set-string 'networkPolicy.relay.allowedCidrs[0]=203.0.113.0/24'

template_ok network-policy-ipv6-source-ranges \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set-string 'agent.apiService.loadBalancerSourceRanges[0]=2001:db8:10::/48' \
  --set networkPolicy.enabled=true \
  --set networkPolicy.acknowledgeHostNetwork=true \
  --set networkPolicy.agentApi.enabled=true \
  --set-string 'networkPolicy.agentApi.allowedCidrs[0]=2001:db8:10:1::/64'

template_fails agent-api-ipv6-network-policy-noncanonical \
  "networkPolicy.agentApi.allowedCidrs entry \"2001:db8:10::1/64\" must be a canonical IPv6 CIDR" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=ClusterIP \
  --set networkPolicy.enabled=true \
  --set networkPolicy.acknowledgeHostNetwork=true \
  --set networkPolicy.agentApi.enabled=true \
  --set-string 'networkPolicy.agentApi.allowedCidrs[0]=2001:db8:10::1/64'

template_fails agent-api-network-policy-broader-than-source-range \
  "networkPolicy.agentApi.allowedCidrs entry \"198.51.0.0/16\" must be contained by one of agent.apiService.loadBalancerSourceRanges values" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set-string 'agent.apiService.loadBalancerSourceRanges[0]=198.51.100.0/24' \
  --set networkPolicy.enabled=true \
  --set networkPolicy.acknowledgeHostNetwork=true \
  --set networkPolicy.agentApi.enabled=true \
  --set-string 'networkPolicy.agentApi.allowedCidrs[0]=198.51.0.0/16'

template_fails agent-api-ipv6-network-policy-broader-than-source-range \
  "networkPolicy.agentApi.allowedCidrs entry \"2001:db8::/32\" must be contained by one of agent.apiService.loadBalancerSourceRanges values" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set-string 'agent.apiService.loadBalancerSourceRanges[0]=2001:db8:10::/48' \
  --set networkPolicy.enabled=true \
  --set networkPolicy.acknowledgeHostNetwork=true \
  --set networkPolicy.agentApi.enabled=true \
  --set-string 'networkPolicy.agentApi.allowedCidrs[0]=2001:db8::/32'

template_fails relay-network-policy-broader-than-source-range \
  "networkPolicy.relay.allowedCidrs entry \"203.0.0.0/16\" must be contained by one of agent.relayService.loadBalancerSourceRanges values" \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=LoadBalancer \
  --set agent.relayService.exposureAcknowledged=true \
  --set-string 'agent.relayService.loadBalancerSourceRanges[0]=203.0.113.0/24' \
  --set networkPolicy.enabled=true \
  --set networkPolicy.acknowledgeHostNetwork=true \
  --set networkPolicy.relay.enabled=true \
  --set-string 'networkPolicy.relay.allowedCidrs[0]=203.0.0.0/16'

template_fails relay-ipv6-network-policy-broader-than-source-range \
  "networkPolicy.relay.allowedCidrs entry \"2001:db8::/32\" must be contained by one of agent.relayService.loadBalancerSourceRanges values" \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=LoadBalancer \
  --set agent.relayService.exposureAcknowledged=true \
  --set-string 'agent.relayService.loadBalancerSourceRanges[0]=2001:db8:20::/48' \
  --set networkPolicy.enabled=true \
  --set networkPolicy.acknowledgeHostNetwork=true \
  --set networkPolicy.relay.enabled=true \
  --set-string 'networkPolicy.relay.allowedCidrs[0]=2001:db8::/32'

template_ok route-disabled \
  --set serviceExposure.enabled=false \
  --set serviceExposure.discoverApiServer=false \
  --set 'serviceExposure.serviceCidrs={}'

template_ok namespaced-service-discovery-rbac \
  --set serviceExposure.discoverServices=true \
  --set serviceExposure.discoverApiServer=false \
  --set-string 'serviceExposure.namespaces[0]=default' \
  --set-string 'serviceExposure.namespaces[1]=platform' \
  --set-string serviceExposure.serviceLabelSelector=ipars.io/expose=true

assert_rendered_contains namespaced-service-discovery-rbac "kind: Role"
assert_rendered_contains namespaced-service-discovery-rbac "kind: RoleBinding"
assert_rendered_contains namespaced-service-discovery-rbac "namespace: default"
assert_rendered_contains namespaced-service-discovery-rbac "namespace: platform"
assert_rendered_contains namespaced-service-discovery-rbac "- --kubernetes-discover-services"
assert_rendered_contains namespaced-service-discovery-rbac "- --kubernetes-namespace"
assert_rendered_contains namespaced-service-discovery-rbac "- --kubernetes-service-label-selector"
assert_rendered_absent namespaced-service-discovery-rbac "kind: ClusterRole"
assert_rendered_absent namespaced-service-discovery-rbac "kind: ClusterRoleBinding"

template_ok relay-forwarder-netns \
  --set agent.securityContext.capabilities.add[0]=NET_ADMIN \
  --set agent.securityContext.capabilities.add[1]=NET_RAW \
  --set agent.securityContext.capabilities.add[2]=SYS_ADMIN \
  --set agent.relayForwarder.enabled=true \
  --set-string agent.relayForwarder.endpoint=127.0.0.1:45182 \
  --set-string agent.relayForwarder.bind=0.0.0.0:45182 \
  --set-string agent.relayForwarder.wireguardEndpoint=127.0.0.1:51820 \
  --set-string agent.relayForwarder.netns=relay-fw

template_fails relay-service-without-advertisement \
  "agent.relayService.enabled=true requires agent.relayAdvertisement.enabled=true" \
  --set agent.relayService.enabled=true

template_fails agent-api-nodeport-without-exposure-ack \
  "agent.apiService external exposure requires agent.apiService.exposureAcknowledged=true" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=NodePort

template_fails relay-nodeport-without-exposure-ack \
  "agent.relayService external exposure requires agent.relayService.exposureAcknowledged=true" \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=NodePort

template_fails agent-api-load-balancer-without-source-control \
  "agent.apiService LoadBalancer exposure requires agent.apiService.loadBalancerSourceRanges or agent.apiService.allowUnrestrictedLoadBalancer=true" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true

template_fails relay-load-balancer-without-source-control \
  "agent.relayService LoadBalancer exposure requires agent.relayService.loadBalancerSourceRanges or agent.relayService.allowUnrestrictedLoadBalancer=true" \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=LoadBalancer \
  --set agent.relayService.exposureAcknowledged=true

template_fails agent-api-unrestricted-load-balancer-with-source-ranges \
  "agent.apiService.allowUnrestrictedLoadBalancer=true cannot be combined with agent.apiService.loadBalancerSourceRanges" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set agent.apiService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.apiService.loadBalancerSourceRanges[0]=198.51.100.0/24'

template_fails relay-unrestricted-load-balancer-with-source-ranges \
  "agent.relayService.allowUnrestrictedLoadBalancer=true cannot be combined with agent.relayService.loadBalancerSourceRanges" \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=LoadBalancer \
  --set agent.relayService.exposureAcknowledged=true \
  --set agent.relayService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.relayService.loadBalancerSourceRanges[0]=203.0.113.0/24'

template_fails agent-api-source-range-annotation \
  "agent.apiService.annotations annotation key \"service.beta.kubernetes.io/load-balancer-source-ranges\" must not configure LoadBalancer source ranges" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set agent.apiService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.apiService.annotations.service\.beta\.kubernetes\.io/load-balancer-source-ranges=198.51.100.0/24'

template_fails relay-inbound-cidr-annotation \
  "agent.relayService.annotations annotation key \"service.beta.kubernetes.io/aws-load-balancer-inbound-cidrs\" must not configure LoadBalancer source ranges" \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=LoadBalancer \
  --set agent.relayService.exposureAcknowledged=true \
  --set agent.relayService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.relayService.annotations.service\.beta\.kubernetes\.io/aws-load-balancer-inbound-cidrs=203.0.113.0/24'

template_fails agent-api-fixed-ip-annotation \
  "agent.apiService.annotations annotation key \"metallb.io/loadBalancerIPs\" must not configure LoadBalancer fixed addresses" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set agent.apiService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.apiService.annotations.metallb\.io/loadBalancerIPs=198.51.100.20'

template_fails agent-api-pip-prefix-annotation \
  "agent.apiService.annotations annotation key \"service.beta.kubernetes.io/azure-pip-prefix-id\" must not configure LoadBalancer fixed addresses" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set agent.apiService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.apiService.annotations.service\.beta\.kubernetes\.io/azure-pip-prefix-id=/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/edge/providers/Microsoft.Network/publicIPPrefixes/prefix'

template_fails relay-eip-annotation \
  "agent.relayService.annotations annotation key \"service.beta.kubernetes.io/aws-load-balancer-eip-allocations\" must not configure LoadBalancer fixed addresses" \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=LoadBalancer \
  --set agent.relayService.exposureAcknowledged=true \
  --set agent.relayService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.relayService.annotations.service\.beta\.kubernetes\.io/aws-load-balancer-eip-allocations=eipalloc-0123456789abcdef0'

template_fails relay-additional-public-ips-annotation \
  "agent.relayService.annotations annotation key \"service.beta.kubernetes.io/azure-additional-public-ips\" must not configure LoadBalancer fixed addresses" \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=LoadBalancer \
  --set agent.relayService.exposureAcknowledged=true \
  --set agent.relayService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.relayService.annotations.service\.beta\.kubernetes\.io/azure-additional-public-ips=198.51.100.80'

template_fails agent-api-proxy-protocol-annotation \
  "agent.apiService.annotations annotation key \"service.beta.kubernetes.io/aws-load-balancer-proxy-protocol\" must not enable PROXY protocol" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set agent.apiService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.apiService.annotations.service\.beta\.kubernetes\.io/aws-load-balancer-proxy-protocol=*'

template_fails relay-health-check-annotation \
  "agent.relayService.annotations annotation key \"service.beta.kubernetes.io/aws-load-balancer-healthcheck-port\" must not configure LoadBalancer health checks" \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=LoadBalancer \
  --set agent.relayService.exposureAcknowledged=true \
  --set agent.relayService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.relayService.annotations.service\.beta\.kubernetes\.io/aws-load-balancer-healthcheck-port=traffic-port'

template_fails agent-api-tls-listener-annotation \
  "agent.apiService.annotations annotation key \"service.beta.kubernetes.io/aws-load-balancer-ssl-cert\" must not configure LoadBalancer TLS, listeners, or backend protocols" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set agent.apiService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.apiService.annotations.service\.beta\.kubernetes\.io/aws-load-balancer-ssl-cert=arn:aws:acm:us-east-1:123456789012:certificate/abcdef'

template_fails agent-api-ha-ports-annotation \
  "agent.apiService.annotations annotation key \"service.beta.kubernetes.io/azure-load-balancer-enable-high-availability-ports\" must not configure LoadBalancer TLS, listeners, or backend protocols" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set agent.apiService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.apiService.annotations.service\.beta\.kubernetes\.io/azure-load-balancer-enable-high-availability-ports=true'

template_fails relay-load-balancer-type-annotation \
  "agent.relayService.annotations annotation key \"cloud.google.com/load-balancer-type\" must not configure LoadBalancer scope or implementation type" \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=LoadBalancer \
  --set agent.relayService.exposureAcknowledged=true \
  --set agent.relayService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.relayService.annotations.cloud\.google\.com/load-balancer-type=Internal'

template_fails agent-api-global-access-annotation \
  "agent.apiService.annotations annotation key \"networking.gke.io/load-balancer-allow-global-access\" must not configure LoadBalancer scope or implementation type" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set agent.apiService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.apiService.annotations.networking\.gke\.io/load-balancer-allow-global-access=true'

template_fails agent-api-l4-rbs-annotation \
  "agent.apiService.annotations annotation key \"cloud.google.com/l4-rbs\" must not configure LoadBalancer scope or implementation type" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set agent.apiService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.apiService.annotations.cloud\.google\.com/l4-rbs=enabled'

template_fails agent-api-security-group-annotation \
  "agent.apiService.annotations annotation key \"service.beta.kubernetes.io/aws-load-balancer-security-groups\" must not configure LoadBalancer firewall or security groups" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set agent.apiService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.apiService.annotations.service\.beta\.kubernetes\.io/aws-load-balancer-security-groups=sg-0123456789abcdef0'

template_fails agent-api-waf-annotation \
  "agent.apiService.annotations annotation key \"service.beta.kubernetes.io/aws-load-balancer-enable-waf\" must not configure LoadBalancer firewall or security groups" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set agent.apiService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.apiService.annotations.service\.beta\.kubernetes\.io/aws-load-balancer-enable-waf=true'

template_fails relay-security-policy-annotation \
  "agent.relayService.annotations annotation key \"networking.gke.io/security-policy\" must not configure LoadBalancer firewall or security groups" \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=LoadBalancer \
  --set agent.relayService.exposureAcknowledged=true \
  --set agent.relayService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.relayService.annotations.networking\.gke\.io/security-policy=edge-armor-policy'

template_fails relay-subnet-annotation \
  "agent.relayService.annotations annotation key \"service.beta.kubernetes.io/aws-load-balancer-subnets\" must not configure LoadBalancer network placement" \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=LoadBalancer \
  --set agent.relayService.exposureAcknowledged=true \
  --set agent.relayService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.relayService.annotations.service\.beta\.kubernetes\.io/aws-load-balancer-subnets=subnet-0123456789abcdef0'

template_fails agent-api-load-balancer-attribute-annotation \
  "agent.apiService.annotations annotation key \"service.beta.kubernetes.io/aws-load-balancer-cross-zone-load-balancing-enabled\" must not configure LoadBalancer operational attributes" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set agent.apiService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.apiService.annotations.service\.beta\.kubernetes\.io/aws-load-balancer-cross-zone-load-balancing-enabled=true'

template_fails agent-api-backend-config-annotation \
  "agent.apiService.annotations annotation key \"cloud.google.com/backend-config\" must not configure LoadBalancer operational attributes" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set agent.apiService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.apiService.annotations.cloud\.google\.com/backend-config=ipars-backend'

template_fails relay-tcp-reset-annotation \
  "agent.relayService.annotations annotation key \"service.beta.kubernetes.io/azure-load-balancer-disable-tcp-reset\" must not configure LoadBalancer operational attributes" \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=LoadBalancer \
  --set agent.relayService.exposureAcknowledged=true \
  --set agent.relayService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.relayService.annotations.service\.beta\.kubernetes\.io/azure-load-balancer-disable-tcp-reset=true'

template_fails agent-api-dns-publication-annotation \
  "agent.apiService.annotations annotation key \"external-dns.alpha.kubernetes.io/hostname\" must not publish LoadBalancer DNS names" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set agent.apiService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.apiService.annotations.external-dns\.alpha\.kubernetes\.io/hostname=api.example.com'

template_fails relay-address-pool-annotation \
  "agent.relayService.annotations annotation key \"metallb.universe.tf/address-pool\" must not configure LoadBalancer resource identity, tags, or address pools" \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=LoadBalancer \
  --set agent.relayService.exposureAcknowledged=true \
  --set agent.relayService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.relayService.annotations.metallb\.universe\.tf/address-pool=public'

template_fails agent-api-load-balancer-mode-annotation \
  "agent.apiService.annotations annotation key \"service.beta.kubernetes.io/azure-load-balancer-mode\" must not configure LoadBalancer resource identity, tags, or address pools" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set agent.apiService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.apiService.annotations.service\.beta\.kubernetes\.io/azure-load-balancer-mode=__auto__'

template_fails relay-load-balancer-configurations-annotation \
  "agent.relayService.annotations annotation key \"service.beta.kubernetes.io/azure-load-balancer-configurations\" must not configure LoadBalancer resource identity, tags, or address pools" \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=LoadBalancer \
  --set agent.relayService.exposureAcknowledged=true \
  --set agent.relayService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.relayService.annotations.service\.beta\.kubernetes\.io/azure-load-balancer-configurations=edge-lb'

template_fails agent-api-private-link-annotation \
  "agent.apiService.annotations annotation key \"service.beta.kubernetes.io/azure-pls-create\" must not configure LoadBalancer Private Link or endpoint-service publishing" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set agent.apiService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.apiService.annotations.service\.beta\.kubernetes\.io/azure-pls-create=true'

template_fails agent-api-target-node-labels-annotation \
  "agent.apiService.annotations annotation key \"service.beta.kubernetes.io/aws-load-balancer-target-node-labels\" must not configure LoadBalancer backend target selection" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set agent.apiService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.apiService.annotations.service\.beta\.kubernetes\.io/aws-load-balancer-target-node-labels=ipars.io/edge=true'

template_fails agent-api-source-nat-annotation \
  "agent.apiService.annotations annotation key \"service.beta.kubernetes.io/azure-disable-load-balancer-snat\" must not configure LoadBalancer source NAT behavior" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set agent.apiService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.apiService.annotations.service\.beta\.kubernetes\.io/azure-disable-load-balancer-snat=true'

template_fails relay-traffic-distribution-annotation \
  "agent.relayService.annotations annotation key \"networking.gke.io/weighted-load-balancing\" must not configure LoadBalancer traffic distribution" \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=LoadBalancer \
  --set agent.relayService.exposureAcknowledged=true \
  --set agent.relayService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.relayService.annotations.networking\.gke\.io/weighted-load-balancing=pods-per-node'

template_fails relay-topology-mode-annotation \
  "agent.relayService.annotations annotation key \"service.kubernetes.io/topology-mode\" must not configure LoadBalancer traffic distribution" \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=LoadBalancer \
  --set agent.relayService.exposureAcknowledged=true \
  --set agent.relayService.allowUnrestrictedLoadBalancer=true \
  --set-string 'agent.relayService.annotations.service\.kubernetes\.io/topology-mode=auto'

template_fails agent-api-external-ip-reuses-load-balancer-ip \
  "agent.apiService.externalIPs entry \"198.51.100.20\" must not reuse fixed external IP assigned by agent.apiService.loadBalancerIP" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set agent.apiService.allowUnrestrictedLoadBalancer=true \
  --set-string agent.apiService.loadBalancerIP=198.51.100.20 \
  --set-string 'agent.apiService.externalIPs[0]=198.51.100.20'

template_fails relay-load-balancer-reuses-agent-api-load-balancer-ip \
  "agent.relayService.loadBalancerIP \"198.51.100.21\" must not reuse fixed external IP assigned by agent.apiService.loadBalancerIP" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set agent.apiService.allowUnrestrictedLoadBalancer=true \
  --set-string agent.apiService.loadBalancerIP=198.51.100.21 \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=LoadBalancer \
  --set agent.relayService.exposureAcknowledged=true \
  --set agent.relayService.allowUnrestrictedLoadBalancer=true \
  --set-string agent.relayService.loadBalancerIP=198.51.100.21

template_fails relay-external-ip-reuses-agent-api-external-ip \
  "agent.relayService.externalIPs entry \"198.51.100.22\" must not reuse fixed external IP assigned by agent.apiService.externalIPs" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=ClusterIP \
  --set agent.apiService.exposureAcknowledged=true \
  --set-string 'agent.apiService.externalIPs[0]=198.51.100.22' \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=ClusterIP \
  --set agent.relayService.exposureAcknowledged=true \
  --set-string 'agent.relayService.externalIPs[0]=198.51.100.22'

template_fails agent-api-load-balancer-ip-family-mismatch \
  "agent.apiService.loadBalancerIP family IPv6 must be included in agent.apiService.ipFamilies" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=LoadBalancer \
  --set agent.apiService.exposureAcknowledged=true \
  --set agent.apiService.allowUnrestrictedLoadBalancer=true \
  --set-string agent.apiService.loadBalancerIP=2001:db8::20 \
  --set-string 'agent.apiService.ipFamilies[0]=IPv4'

template_fails relay-external-ip-family-mismatch \
  "agent.relayService.externalIPs entry \"203.0.113.23\" family IPv4 must be included in agent.relayService.ipFamilies" \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=ClusterIP \
  --set agent.relayService.exposureAcknowledged=true \
  --set-string 'agent.relayService.externalIPs[0]=203.0.113.23' \
  --set-string 'agent.relayService.ipFamilies[0]=IPv6'

template_fails host-network-policy-without-ack \
  "networkPolicy with agent.hostNetwork=true requires networkPolicy.acknowledgeHostNetwork=true" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=ClusterIP \
  --set networkPolicy.enabled=true \
  --set networkPolicy.agentApi.enabled=true \
  --set-string 'networkPolicy.agentApi.allowedCidrs[0]=10.0.0.0/8'

template_fails agent-api-cluster-external-traffic-policy-without-ack \
  "agent.apiService externalTrafficPolicy=Cluster requires agent.apiService.allowClusterExternalTrafficPolicy=true" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=NodePort \
  --set agent.apiService.exposureAcknowledged=true \
  --set agent.apiService.externalTrafficPolicy=Cluster

template_fails relay-cluster-external-traffic-policy-without-ack \
  "agent.relayService externalTrafficPolicy=Cluster requires agent.relayService.allowClusterExternalTrafficPolicy=true" \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=NodePort \
  --set agent.relayService.exposureAcknowledged=true \
  --set agent.relayService.externalTrafficPolicy=Cluster

template_fails cluster-control-plane-url-userinfo \
  "cluster.controlPlaneUrl must not include userinfo" \
  --set-string cluster.controlPlaneUrl=https://user:pass@control.example.com:8443

template_fails cluster-signal-url-invalid-port \
  "cluster.signalUrl port must be between 1 and 65535" \
  --set-string cluster.signalUrl=https://signal.example.com:99999

template_fails cluster-stun-endpoint-unspecified \
  "cluster.stunEndpoint value \"0.0.0.0:3478\" must not use an unspecified address" \
  --set-string cluster.stunEndpoint=0.0.0.0:3478

template_fails name-override-invalid \
  "nameOverride \"Bad_Name\" must be a DNS label of at most 53 bytes" \
  --set-string nameOverride=Bad_Name

template_fails scheduler-name-invalid \
  "agent.schedulerName must be a Kubernetes DNS subdomain" \
  --set-string agent.schedulerName=system/scheduler

template_fails runtime-class-invalid \
  "agent.runtimeClassName must be a Kubernetes DNS subdomain" \
  --set-string agent.runtimeClassName=Runtime_Class

template_fails node-affinity-in-without-values \
  "agent.nodeAffinity.required.matchExpressions[0].values is required when operator is In" \
  --set-string 'agent.nodeAffinity.required.matchExpressions[0].key=kubernetes.io/os' \
  --set-string 'agent.nodeAffinity.required.matchExpressions[0].operator=In'

template_fails node-affinity-preferred-zero-weight \
  "agent.nodeAffinity.preferred[0].weight must be between 1 and 100" \
  --set 'agent.nodeAffinity.preferred[0].weight=0' \
  --set-string 'agent.nodeAffinity.preferred[0].matchExpressions[0].key=node-role.kubernetes.io/worker' \
  --set-string 'agent.nodeAffinity.preferred[0].matchExpressions[0].operator=Exists'

template_fails pod-affinity-in-without-values \
  "agent.podAffinity.required[0].matchExpressions[0].values is required when operator is In" \
  --set-string 'agent.podAffinity.required[0].topologyKey=kubernetes.io/hostname' \
  --set-string 'agent.podAffinity.required[0].matchExpressions[0].key=app.kubernetes.io/name' \
  --set-string 'agent.podAffinity.required[0].matchExpressions[0].operator=In'

template_fails pod-affinity-preferred-zero-weight \
  "agent.podAntiAffinity.preferred[0].weight must be between 1 and 100" \
  --set 'agent.podAntiAffinity.preferred[0].weight=0' \
  --set-string 'agent.podAntiAffinity.preferred[0].topologyKey=kubernetes.io/hostname' \
  --set-string 'agent.podAntiAffinity.preferred[0].matchExpressions[0].key=app.kubernetes.io/name' \
  --set-string 'agent.podAntiAffinity.preferred[0].matchExpressions[0].operator=Exists'

template_fails topology-spread-zero-max-skew \
  "agent.topologySpreadConstraints[0].maxSkew must be greater than zero" \
  --set-string 'agent.topologySpreadConstraints[0].topologyKey=topology.kubernetes.io/zone' \
  --set 'agent.topologySpreadConstraints[0].maxSkew=0' \
  --set-string 'agent.topologySpreadConstraints[0].whenUnsatisfiable=DoNotSchedule'

template_fails topology-spread-min-domains-schedule-anyway \
  "agent.topologySpreadConstraints[0].minDomains requires whenUnsatisfiable=DoNotSchedule" \
  --set-string 'agent.topologySpreadConstraints[0].topologyKey=topology.kubernetes.io/zone' \
  --set 'agent.topologySpreadConstraints[0].maxSkew=1' \
  --set-string 'agent.topologySpreadConstraints[0].whenUnsatisfiable=ScheduleAnyway' \
  --set 'agent.topologySpreadConstraints[0].minDomains=2'

template_fails relay-forwarder-netns-without-sys-admin \
  "agent.relayForwarder.netns requires agent.privileged=true or SYS_ADMIN in agent.securityContext.capabilities.add" \
  --set agent.relayForwarder.enabled=true \
  --set-string agent.relayForwarder.endpoint=127.0.0.1:45182 \
  --set-string agent.relayForwarder.bind=0.0.0.0:45182 \
  --set-string agent.relayForwarder.wireguardEndpoint=127.0.0.1:51820 \
  --set-string agent.relayForwarder.netns=relay-fw

template_fails agent-state-hostpath-sensitive-system-path \
  "agent.state.hostPath must not be a sensitive system path" \
  --set-string agent.state.hostPath=/etc/ipars

template_fails agent-state-mountpath-sensitive-system-path \
  "agent.state.mountPath must not be a sensitive system path" \
  --set-string agent.state.mountPath=/proc/ipars

echo "Helm smoke checks passed using ${helm_image}"
