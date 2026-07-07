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
  if ! grep -Fq "$expected" "$rendered"; then
    echo "Helm template output for ${name} did not include expected content: ${expected}" >&2
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

template_fails host-network-policy-without-ack \
  "networkPolicy with agent.hostNetwork=true requires networkPolicy.acknowledgeHostNetwork=true" \
  --set agent.apiService.enabled=true \
  --set agent.apiService.type=ClusterIP \
  --set networkPolicy.enabled=true \
  --set networkPolicy.agentApi.enabled=true \
  --set-string 'networkPolicy.agentApi.allowedCidrs[0]=10.0.0.0/8'

template_fails relay-forwarder-netns-without-sys-admin \
  "agent.relayForwarder.netns requires agent.privileged=true or SYS_ADMIN in agent.securityContext.capabilities.add" \
  --set agent.relayForwarder.enabled=true \
  --set-string agent.relayForwarder.endpoint=127.0.0.1:45182 \
  --set-string agent.relayForwarder.bind=0.0.0.0:45182 \
  --set-string agent.relayForwarder.wireguardEndpoint=127.0.0.1:51820 \
  --set-string agent.relayForwarder.netns=relay-fw

echo "Helm smoke checks passed using ${helm_image}"
