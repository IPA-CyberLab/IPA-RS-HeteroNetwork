"""Pure preparation for the fixed DEV resize; no libvirt or guest operations."""
import copy
import uuid
import xml.etree.ElementTree as ET

TARGET_VCPU = 8
TARGET_MEMORY_MIB = 10240
HOST_RESERVE_MIB = 24576
GUESTS = ('hetero-dev-1', 'hetero-dev-2', 'hetero-dev-3')
STAGES = {'core': ((4, 8192), (8, 10240)), 'services': ((8, 10240), (12, 12288))}


def require(value):
    if not value:
        raise ValueError('Unreviewed DEV capacity definition')


def without_capacity(text):
    root = ET.fromstring(text)
    for tag in ('vcpu', 'memory', 'currentMemory'):
        for node in root.findall(tag):
            root.remove(node)
    return ET.canonicalize(ET.tostring(root, encoding='unicode'), strip_text=True)


def target(stage):
    require(stage in STAGES)
    return STAGES[stage][1]


def requested_xml(text, name, stage='core'):
    require(name in GUESTS)
    target_cpu, target_memory = target(stage)
    root = ET.fromstring(text)
    expected = str(uuid.uuid5(uuid.NAMESPACE_URL, f'urn:heteronetwork:dev:ichikawap1:domain:{name}'))
    require(root.tag == 'domain' and root.get('type') == 'kvm'
            and root.findtext('name') == name and root.findtext('uuid') == expected)
    require(not any(root.findall(tag) for tag in ('maxMemory', 'vcpus', 'cputune', 'numatune', 'memoryBacking')))
    require(root.find('cpu/topology') is None)
    require(all(len(root.findall(tag)) == 1 for tag in ('vcpu', 'memory', 'currentMemory')))
    vcpu = root.find('vcpu')
    require(vcpu.attrib == {'placement': 'static'})
    memory, current = root.find('memory'), root.find('currentMemory')
    require(memory.attrib == current.attrib == {'unit': 'KiB'}
            and memory.text == current.text)
    require((vcpu.text, memory.text) in {(str(cpu), str(mib * 1024)) for cpu, mib in STAGES[stage]})
    result = copy.deepcopy(root)
    result.find('vcpu').text = str(target_cpu)
    for tag in ('memory', 'currentMemory'):
        result.find(tag).text = str(target_memory * 1024)
    result = ET.tostring(result, encoding='unicode')
    require(without_capacity(result) == without_capacity(text))
    return result


def static_budget(host_memory_kib, host_cpus, other_memory_kib, other_vcpus, stage='core'):
    target_cpu, target_memory = target(stage)
    require(all(type(v) is int and v > 0 for v in
                (host_memory_kib, host_cpus, other_memory_kib, other_vcpus)))
    committed = 3 * target_memory * 1024 + other_memory_kib
    reserved = committed + HOST_RESERVE_MIB * 1024
    vcpus = 3 * target_cpu + other_vcpus
    return {'target_vcpu_per_guest': target_cpu, 'target_memory_mib_per_guest': target_memory,
            'vm_committed_memory_kib': committed, 'with_host_reserve_kib': reserved,
            'host_memory_margin_kib': host_memory_kib - reserved, 'total_vm_vcpus': vcpus,
            'static_totals_fit': reserved <= host_memory_kib and vcpus <= host_cpus,
            'live_admission_verified': False, 'restart_authorized': False,
            'runtime_changed': False}
