# Stopped VPN peer reappearing on control-plane nodes

On 2026-11-01, while preparing the HeteroCloud IAM rollout, `uc-k8sp4` was
declared stopped and had been unreachable for several days. Its old API and
worker Pods remained terminating and were not ready service endpoints.

The active WireGuard state on `uc-k8sp1` and `uc-k8sp2` nevertheless contained
the stopped node's declared public key and `10.250.0.11/32` route. Removing that
exact key from each interface worked initially, but the key reappeared after
the agents synchronized again. Their heartbeats repeatedly received HTTP 403:
the submitted path state included the stopped node, which the control plane
correctly reported was no longer visible. The other three active cluster nodes
did not have that stopped peer in the inspected interface state.

The stopped node's overlay IPv4 address is now fenced in both directions on
all five active cluster nodes, independently of whether the agent re-adds the
peer. The rules cover INPUT, OUTPUT and FORWARD, precede the existing firewall
rules, are restored on boot before the VPN agent starts, and are reconciled by
a systemd timer. The lifecycle Ansible playbook also removes declared stopped
WireGuard keys without touching active keys. Resuming a node through the roster
removes its fence on the next infrastructure reconciliation.

The firewall implementation was tested using real packets in a disposable
network namespace, including resuming the node and retaining connectivity to an
unrelated address. Terraform/Ansible declare the changes; the playbook was
applied to the five reachable nodes. The HeteroCloud rollout then verified the
running image digest and ready endpoints before activating IAM controls.

The two affected agents were restarted one at a time. Both resumed successful
heartbeats, and their Kubernetes nodes and overlay connectivity remained ready
through the checks. The stopped node's WireGuard key was still reintroduced;
the exact reintroduction mechanism has not been resolved. The firewall remains
the traffic fence, and the heartbeat recovery needs continued monitoring. Do
not reactivate `uc-k8sp4` without first reconciling its old workloads and
confirming current software and cluster membership.
