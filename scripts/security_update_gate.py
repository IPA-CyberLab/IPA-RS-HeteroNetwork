#!/usr/bin/env python3
"""Validate exact, fresh evidence before an automated security change.

Compatibility proof is an acceptance result, never an operator's assertion that
an arbitrary checkpoint format can be migrated. Missing evidence blocks the
change and leaves the existing workload running. Binary installation and active
process remediation are separate outcomes.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def assess(plan, proof, policy, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    reasons = []
    if plan.get('severity') not in policy['auto_patch_severities']:
        reasons.append('severity_not_in_policy')
    if not plan.get('cves') or not plan.get('fixed_version'):
        reasons.append('no_verified_fix')
    if not plan.get('source_sha256') or len(plan['source_sha256']) != 64:
        reasons.append('artifact_not_pinned')
    try:
        age = (now - datetime.datetime.fromisoformat(proof['verified_at'])).total_seconds()
        if age < 0 or age > policy['proof_max_age_seconds']:
            reasons.append('stale_proof')
    except (KeyError, TypeError, ValueError):
        reasons.append('missing_proof_timestamp')
    if proof.get('plan_sha256') != fingerprint(plan):
        reasons.append('proof_for_different_plan')
    for field in ('ci_passed', 'candidate_rescan_passed', 'service_health_passed', 'rollback_verified'):
        if proof.get(field) is not True:
            reasons.append(field + '_required')
    if policy['require_live_migration'] and plan.get('running_workloads'):
        for field in ('state_preserved', 'network_connections_preserved', 'target_runtime_verified', 'source_fenced', 'capacity_reserved'):
            if proof.get(field) is not True:
                reasons.append(field + '_required')
        if proof.get('strategy') not in ('gvisor_checkpoint_restore', 'vm_live_migration'):
            reasons.append('live_migration_required')
        if plan.get('gpu') and proof.get('gpu_state_preserved') is not True:
            reasons.append('gpu_state_preservation_required')
        if plan.get('from_runtime') != plan.get('to_runtime') and proof.get('cross_version_restore_passed') is not True:
            reasons.append('cross_version_restore_unverified')
    if plan.get('inventory_complete') is not True:
        reasons.append('inventory_incomplete')
    if plan.get('fleet_healthy') is not True:
        reasons.append('fleet_unhealthy')
    if plan.get('generation') != proof.get('generation'):
        reasons.append('workload_generation_changed')
    if not policy['allow_restart_fallback'] and proof.get('restart_fallback'):
        reasons.append('restart_fallback_forbidden')
    return {'allowed': not reasons, 'status': 'ready' if not reasons else 'blocked', 'reasons': reasons, 'plan_sha256': fingerprint(plan)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--plan', required=True)
    p.add_argument('--proof', required=True)
    p.add_argument('--policy', required=True)
    a = p.parse_args()
    result = assess(*[json.loads(Path(path).read_text()) for path in [a.plan, a.proof, a.policy]])
    print(json.dumps(result))
    raise SystemExit(0 if result['allowed'] else 1)


if __name__ == '__main__':
    main()
