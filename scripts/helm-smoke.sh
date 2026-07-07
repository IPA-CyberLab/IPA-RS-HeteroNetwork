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

template_ok agent-api \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=ClusterIP

template_ok relay-service \
  --set agent.relayAdvertisement.enabled=true \
  --set-string agent.relayAdvertisement.publicEndpoint=203.0.113.10:51820 \
  --set-string agent.relayAdvertisement.admissionUrl=http://relay.example.com:9580 \
  --set agent.relayService.enabled=true \
  --set agent.relayService.type=ClusterIP

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

template_fails relay-forwarder-netns-without-sys-admin \
  "agent.relayForwarder.netns requires agent.privileged=true or SYS_ADMIN in agent.securityContext.capabilities.add" \
  --set agent.relayForwarder.enabled=true \
  --set-string agent.relayForwarder.endpoint=127.0.0.1:45182 \
  --set-string agent.relayForwarder.bind=0.0.0.0:45182 \
  --set-string agent.relayForwarder.wireguardEndpoint=127.0.0.1:51820 \
  --set-string agent.relayForwarder.netns=relay-fw

echo "Helm smoke checks passed using ${helm_image}"
