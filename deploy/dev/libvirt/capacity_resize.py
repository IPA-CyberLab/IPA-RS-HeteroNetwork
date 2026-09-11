"""Pure preparation for the fixed DEV resize; no libvirt or guest operations."""
import copy
import uuid
import xml.etree.ElementTree as ET

TARGET_VCPU = 8
TARGET_MEMORY_MIB = 10240
HOST_RESERVE_MIB = 24576
GUESTS = ('hetero-dev-1', 'hetero-dev-2', 'hetero-dev-3')


def require(value):
    if not value:
        raise ValueError('Unreviewed DEV capacity definition')


def without_capacity(text):
    root = ET.fromstring(text)
    for tag in ('vcpu', 'memory', 'currentMemory'):
        for node in root.findall(tag):
            root.remove(node)
    return ET.canonicalize(ET.tostring(root, encoding='unicode'), strip_text=True)


def requested_xml(text, name):
    require(name in GUESTS)
    root = ET.fromstring(text)
    expected = str(uuid.uuid5(uuid.NAMESPACE_URL, f'urn:heteronetwork:dev:ichikawap1:domain:{name}'))
    require(root.tag == 'domain' and root.get('type') == 'kvm'
            and root.findtext('name') == name and root.findtext('uuid') == expected)
    require(not any(root.findall(tag) for tag in ('maxMemory', 'vcpus', 'cputune', 'numatune', 'memoryBacking')))
    require(root.find('cpu/topology') is None)
    require(all(len(root.findall(tag)) == 1 for tag in ('vcpu', 'memory', 'currentMemory')))
    vcpu = root.find('vcpu')
    require(vcpu.attrib == {'placement': 'static'} and vcpu.text in ('4', str(TARGET_VCPU)))
    memory, current = root.find('memory'), root.find('currentMemory')
    require(memory.attrib == current.attrib == {'unit': 'KiB'}
            and memory.text == current.text
            and memory.text in (str(8192 * 1024), str(TARGET_MEMORY_MIB * 1024)))
    require((vcpu.text == '4') == (memory.text == str(8192 * 1024)))
    result = copy.deepcopy(root)
    result.find('vcpu').text = str(TARGET_VCPU)
    for tag in ('memory', 'currentMemory'):
        result.find(tag).text = str(TARGET_MEMORY_MIB * 1024)
    result = ET.tostring(result, encoding='unicode')
    require(without_capacity(result) == without_capacity(text))
    return result


def static_budget(host_memory_kib, host_cpus, other_memory_kib, other_vcpus):
    require(all(type(v) is int and v > 0 for v in
                (host_memory_kib, host_cpus, other_memory_kib, other_vcpus)))
    committed = 3 * TARGET_MEMORY_MIB * 1024 + other_memory_kib
    reserved = committed + HOST_RESERVE_MIB * 1024
    vcpus = 3 * TARGET_VCPU + other_vcpus
    return {'target_vcpu_per_guest': TARGET_VCPU, 'target_memory_mib_per_guest': TARGET_MEMORY_MIB,
            'vm_committed_memory_kib': committed, 'with_host_reserve_kib': reserved,
            'host_memory_margin_kib': host_memory_kib - reserved, 'total_vm_vcpus': vcpus,
            'static_totals_fit': reserved <= host_memory_kib and vcpus <= host_cpus,
            'live_admission_verified': False, 'restart_authorized': False,
            'runtime_changed': False}
