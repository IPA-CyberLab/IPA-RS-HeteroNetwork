#!/usr/bin/env python3
"""Exercise DNS quorum and a real external witness in an isolated namespace.

Only fixture Pods and an .invalid DNSEndpoint are changed. The external-dns
domain filter excludes .invalid, so no public or tenant DNS records are written.
"""
import argparse
import base64
import copy
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
import uuid
import yaml

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / 'deploy/gitops/public-dns-quorum'
sys.path.insert(0, str(MODULE))
import controller as quorum
import render


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--keep-on-failure', action='store_true')
    parser.add_argument('--simulate-remote-failure', action='store_true',
                        help='create and delete a temporary Worker to test a failed remote origin')
    args = parser.parse_args()
    nonce = uuid.uuid4().hex[:10]
    namespace = 'dns-witness-e2e-' + nonce
    config = json.loads((MODULE / 'pool.json').read_text())
    assert len(config['members']) == 2 and len(config['origins']) == 2 and config.get('witness')
    config.update(namespace=namespace, dns_namespace=namespace, dns_resource='fixture',
                  state_resource='fixture-state', records=['witness-' + nonce + '.invalid'], enabled=True)
    quorum.validate_config(config)
    report = {'passed': False, 'namespace': namespace, 'public_dns_changed': False,
              'production_pods_modified': False, 'checks': []}
    fixture_worker = None
    worker_dir = None
    fixture_token = None
    worker_inventory = None
    worker_may_exist = False
    args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    def save():
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        args.output.chmod(0o600)

    def check(name):
        report['checks'].append(name)
        save()
        print('PASS ' + name, flush=True)

    def kube(*argv, body=None, success=True):
        result = subprocess.run(['kubectl', '--request-timeout=15s', *argv],
            input=None if body is None else yaml.safe_dump_all(body, sort_keys=False),
            text=True, capture_output=True, timeout=30)
        if success and result.returncode:
            # Inputs can contain a Secret; never print kubectl's diagnostics.
            raise RuntimeError('fixture Kubernetes operation failed')
        return result

    def get(kind, name):
        return json.loads(kube('-n', namespace, 'get', kind, name, '-o', 'json').stdout)

    def status():
        return json.loads(get('configmap', config['state_resource']).get('data', {}).get('status.json', '{}'))

    def targets():
        return sorted(get('dnsendpoint', config['dns_resource'])['spec']['endpoints'][0]['targets'])

    def wait(predicate, seconds=180):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(2)
        raise RuntimeError('fixture did not converge')

    def apply(docs):
        kube('apply', '-f', '-', body=docs)

    def owned():
        result = kube('get', 'namespace', namespace, '-o', 'json', success=False)
        return result.returncode == 0 and json.loads(result.stdout)['metadata'].get('labels', {}).get('dns.heterocloud.io/e2e-owner') == nonce

    def deploy_fixture_worker(fail_origin=None):
        origins = copy.deepcopy(worker_inventory)
        for origin in origins:
            if origin['id'] == fail_origin:
                # This name has a valid wildcard TLS certificate but no health
                # route. Only this fixture Worker is given the altered name.
                origin['host'] = 'unrouted-' + nonce + '.flash.heterocloud.mizuame.app'
        (worker_dir / 'wrangler.toml').write_text(
            'name = "' + fixture_worker + '"\nmain = "worker.mjs"\n'
            'compatibility_date = "2026-10-01"\nworkers_dev = true\n[vars]\n'
            "WITNESS_ORIGINS = '" + json.dumps(origins, separators=(',', ':')) + "'\n")
        deployment = subprocess.run(['wrangler', 'deploy'], cwd=worker_dir, text=True,
                                    capture_output=True, timeout=90)
        if deployment.returncode:
            raise RuntimeError('temporary witness deployment failed')
        matches = re.findall(r'https://' + re.escape(fixture_worker) + r'\.[a-z0-9.-]+\.workers\.dev', deployment.stdout)
        if not matches:
            raise RuntimeError('temporary witness URL not found')
        result = subprocess.run(['wrangler', 'secret', 'put', 'WITNESS_TOKEN'], cwd=worker_dir,
                                input=fixture_token + '\n', text=True, capture_output=True, timeout=60)
        if result.returncode:
            raise RuntimeError('temporary witness setup failed')
        url = matches[0] + '/v1/probe'
        deadline = time.monotonic() + 30
        while True:
            request = urllib.request.Request(url + '?nonce=' + uuid.uuid4().hex,
                headers={'Authorization':'Bearer ' + fixture_token,'User-Agent':'HeteroNetwork-DNS-Publisher/1.0'})
            try:
                with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=12) as response:
                    observation = json.load(response)['origins']
                if all(observation[x['id']]['healthy'] == (x['id'] != fail_origin) for x in origins):
                    break
            except (OSError, ValueError, KeyError, urllib.error.URLError):
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError('temporary witness probe did not match fixture')
            time.sleep(2)
        return url

    stage = 'create'
    try:
        if args.simulate_remote_failure:
            fixture_worker = 'heteronetwork-witness-e2e-' + nonce
            fixture_token = secrets.token_hex(32)
            worker_dir = Path(tempfile.mkdtemp(prefix='heteronetwork-witness-e2e-'))
            shutil.copyfile(ROOT/'deploy/public-dns-witness/worker.mjs', worker_dir/'worker.mjs')
            worker_config = tomllib.loads((ROOT/'deploy/public-dns-witness/wrangler.toml').read_text())
            worker_inventory = json.loads(worker_config['vars']['WITNESS_ORIGINS'])
            stage = 'temporary_witness'
            existing = subprocess.run(['wrangler','deployments','list','--name',fixture_worker], cwd=worker_dir,
                                      capture_output=True, text=True, timeout=60)
            if existing.returncode == 0 or '10007' not in existing.stdout + existing.stderr:
                raise RuntimeError('temporary witness name is not confirmed unused')
            worker_may_exist = True
            config['witness']['url'] = deploy_fixture_worker()
            quorum.validate_config(config)
        assert kube('get', 'namespace', namespace, success=False).returncode != 0
        apply([{'apiVersion':'v1','kind':'Namespace','metadata':{'name':namespace,
            'labels':{'dns.heterocloud.io/e2e-owner':nonce}}}])
        assert owned()
        if fixture_token:
            secret_data = {'token':base64.b64encode(fixture_token.encode()).decode()}
        else:
            secret = json.loads(kube('-n', 'heterocloud-dns', 'get', 'secret', 'public-dns-witness-token', '-o', 'json').stdout)
            assert set(secret['data']) == {'token'}
            secret_data = secret['data']
        docs = render.objects(config)
        docs += [{'apiVersion':'v1','kind':'Secret','metadata':{'name':'public-dns-witness-token','namespace':namespace},
                  'type':'Opaque','data':secret_data},
                 {'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':'public-dns-quorum-runtime','namespace':namespace},
                  'data':{'controller.py':(MODULE/'controller.py').read_text(),'pool.json':json.dumps(config)}},
                 {'apiVersion':'externaldns.k8s.io/v1alpha1','kind':'DNSEndpoint',
                  'metadata':{'name':config['dns_resource'],'namespace':namespace,'labels':{'dns.heterocloud.io/publish':'true'}},
                  'spec':{'endpoints':[{'dnsName':config['records'][0],'recordType':'A','recordTTL':60,
                                       'targets':[x['address'] for x in config['origins']]}]}}]
        apply(docs)
        base = next(x for x in docs if x['kind'] == 'NetworkPolicy' and x['metadata']['name'] == render.APP)
        witness_policy = next(x for x in docs if x['kind'] == 'NetworkPolicy' and x['metadata']['name'] == render.APP + '-witness')
        both = sorted(x['address'] for x in config['origins'])
        victim, survivor = config['origins']

        stage = 'initial_observations'
        wait(lambda: status().get('fresh_voters') == 2 and all(
            x['decision'] == 'healthy' for x in status().get('origins', {}).values()))
        assert targets() == both
        check('two_real_voters_observe_both_gateways')

        def policies(blocked):
            result = []
            for member in config['members']:
                value = copy.deepcopy(base)
                value['metadata']['name'] = 'fixture-voter-' + member['id']
                value['spec']['podSelector']['matchLabels'].update({'app.kubernetes.io/component':'voter',
                    'dns.heterocloud.io/voter-id':member['id']})
                allowed = [x for x in config['origins'] if x['id'] not in blocked.get(member['id'], [])]
                value['spec']['egress'] = value['spec']['egress'][:1] + ([{'to':[{'ipBlock':{'cidr':x['address']+'/32'}} for x in allowed],
                    'ports':[{'protocol':'TCP','port':80},{'protocol':'TCP','port':443}]}] if allowed else [])
                result.append(value)
            publisher = copy.deepcopy(base)
            publisher['metadata']['name'] = 'fixture-publisher'
            publisher['spec']['podSelector']['matchLabels']['app.kubernetes.io/component'] = 'publisher'
            publisher['spec']['egress'] = publisher['spec']['egress'][:1]
            apply(result + [publisher])

        policies({})
        kube('-n', namespace, 'delete', 'networkpolicy', render.APP)
        first, second = config['members']
        stage = 'one_partitioned_observer'
        policies({first['id']:[victim['id']]})
        wait(lambda: status().get('witness', {}).get('polled') is True and
             status().get('witness', {}).get('available') is True and
             status().get('origins', {}).get(victim['id'], {}).get('healthy_votes') == 2 and
             status().get('origins', {}).get(victim['id'], {}).get('unhealthy_votes') == 1)
        assert targets() == both
        check('external_witness_prevents_one_partitioned_observer_from_withdrawing_dns')

        stage = 'majority_withdrawal'
        policies({first['id']:[victim['id']],second['id']:[victim['id']]})
        wait(lambda: targets() == [survivor['address']])
        check('two_independent_observers_remove_failed_origin_in_fixture')

        stage = 'recovery'
        policies({})
        wait(lambda: targets() == both and all(x['decision'] == 'healthy' for x in status().get('origins', {}).values()))
        check('recovered_origin_is_readded_in_fixture')

        stage = 'local_voter_unavailable'
        kube('-n', namespace, 'scale', 'deployment/public-dns-voter-' + first['id'], '--replicas=0')
        wait(lambda: status().get('witness', {}).get('polled') is True and
             status().get('witness', {}).get('available') is True and status().get('fresh_voters') == 2)
        assert targets() == both
        check('one_surviving_voter_and_external_witness_form_majority')

        stage = 'external_witness_unavailable'
        kube('-n', namespace, 'delete', 'networkpolicy', render.APP + '-witness')
        wait(lambda: status().get('witness', {}).get('polled') is True and
             status().get('witness', {}).get('available') is False and status().get('fresh_voters') == 1)
        assert targets() == both
        assert all(x['decision'] == 'unknown' for x in status().get('origins', {}).values())
        check('loss_of_majority_keeps_dns_without_lowering_quorum')
        apply([witness_policy])
        if fixture_worker:
            stage = 'external_witness_confirms_failed_origin'
            deploy_fixture_worker(fail_origin=victim['id'])
            policies({second['id']:[victim['id']]})
            wait(lambda: targets() == [survivor['address']] and
                 status().get('witness', {}).get('available') is True and
                 status().get('origins', {}).get(victim['id'], {}).get('decision') == 'unhealthy')
            check('one_surviving_voter_and_external_witness_withdraw_failed_origin')
            stage = 'external_witness_confirms_recovery'
            deploy_fixture_worker()
            policies({})
            wait(lambda: targets() == both and status().get('witness', {}).get('available') is True)
            check('one_surviving_voter_and_external_witness_restore_recovered_origin')
        report['passed'] = True
        save()
    except Exception:
        report['failure_stage'] = stage
        save()
        print('Witness verification failed at ' + stage + '; credentials are excluded', file=sys.stderr)
    finally:
        if owned() and (report['passed'] or not args.keep_on_failure):
            result = kube('delete', 'namespace', namespace, '--wait=false', success=False)
            report['fixture_removal_requested'] = result.returncode == 0
        if worker_may_exist and worker_dir:
            result = subprocess.run(['wrangler','delete',fixture_worker,'--force'], cwd=worker_dir,
                                    capture_output=True, text=True, timeout=60)
            report['temporary_worker_removed'] = result.returncode == 0
        if worker_dir:
            shutil.rmtree(worker_dir, ignore_errors=True)
        save()
    return 0 if (report['passed'] and report.get('fixture_removal_requested') and
                 (not fixture_worker or report.get('temporary_worker_removed'))) else 1


if __name__ == '__main__':
    raise SystemExit(main())
