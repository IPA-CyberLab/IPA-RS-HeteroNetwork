"""Offline declared-request accounting. This is not a scheduler or host admission."""
from decimal import Decimal, ROUND_CEILING
import re

FACTORS = {'': Decimal(1), 'n': Decimal('1e-9'), 'u': Decimal('1e-6'), 'm': Decimal('1e-3')}
FACTORS.update({s: Decimal(1000) ** i for i, s in enumerate(('k', 'M', 'G', 'T', 'P', 'E'), 1)})
FACTORS['K'] = FACTORS['k']
FACTORS.update({s: Decimal(1024) ** i for i, s in enumerate(('Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei'), 1)})


def quantity(value):
    text = str(value)
    match = re.fullmatch(r'([+]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+))([A-Za-z]+|[eE][+-]?[0-9]+)?', text)
    if not match:
        raise ValueError('Unsupported or negative resource quantity')
    number, suffix = match.groups()
    suffix = suffix or ''
    if suffix not in FACTORS:
        if not re.fullmatch(r'[eE][+-]?[0-9]+', suffix):
            raise ValueError('Unsupported resource suffix')
        return Decimal(number + suffix)
    return Decimal(number) * FACTORS[suffix]


def requests(container):
    resources = container.get('resources', {})
    req, limits = resources.get('requests', {}), resources.get('limits', {})
    return {key: quantity(req.get(key, limits.get(key, '0'))) for key in ('cpu', 'memory')}


def pod_requests(pod):
    if pod.get('resources'):
        raise ValueError('Pod-level resources require a separate accounting implementation')
    if any(c.get('restartPolicy') == 'Always' for c in pod.get('initContainers', [])):
        raise ValueError('Restartable init containers require sidecar-aware accounting')
    result = {key: sum((requests(c)[key] for c in pod.get('containers', [])), Decimal(0))
              for key in ('cpu', 'memory')}
    for init in pod.get('initContainers', []):
        result = {key: max(result[key], requests(init)[key]) for key in result}
    return {key: result[key] + quantity(pod.get('overhead', {}).get(key, '0')) for key in result}


def units(value):
    return {'cpu_millicores': int((value['cpu'] * 1000).to_integral_value(rounding=ROUND_CEILING)),
            'memory_bytes': int(value['memory'].to_integral_value(rounding=ROUND_CEILING))}


def workloads(documents, namespace):
    rows = []
    for item in documents:
        if not item:
            continue
        kind, spec = item.get('kind'), item.get('spec', {})
        if kind in ('Deployment', 'StatefulSet'):
            replicas, pod = spec.get('replicas', 1), spec['template']['spec']
        elif kind == 'Job':
            replicas, pod = spec.get('parallelism', 1), spec['template']['spec']
        elif kind == 'Cluster' and item.get('apiVersion') == 'postgresql.cnpg.io/v1':
            replicas, pod = spec['instances'], {'containers': [{'resources': spec['resources']}]}
        elif kind in ('DaemonSet', 'CronJob', 'Pod'):
            raise ValueError('Explicit placement/count required for ' + kind)
        else:
            continue
        if type(replicas) is not int or replicas < 0:
            raise ValueError('Invalid workload replica count')
        request = pod_requests(pod)
        rows.append({'namespace': item['metadata'].get('namespace', namespace), 'kind': kind,
                     'name': item['metadata']['name'], 'replicas': replicas,
                     'transient': kind == 'Job', 'per_pod': units(request),
                     'total': units({k: v * replicas for k, v in request.items()}),
                     'missing_requests': [c.get('name', 'unnamed') for c in pod.get('containers', [])
                                          if any(k not in c.get('resources', {}).get('requests', {})
                                                 and k not in c.get('resources', {}).get('limits', {})
                                                 for k in ('cpu', 'memory'))]})
    return rows
