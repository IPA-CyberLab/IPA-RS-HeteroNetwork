#!/usr/bin/env python3
"""Disposable KVM workers: iSCSI needs its own kernel, not a Docker network namespace."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import time
import urllib.request

ROOT = Path('/tmp/hnn-heartbeat-e2e')
CLUSTER = 'hnn-heartbeat-e2e'
CP = CLUSTER + '-control-plane'


def run(command, timeout=30, data=None):
    try:
        p = subprocess.run(command, input=data, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        # TimeoutExpired normally embeds argv, including kubeadm's short-lived token.
        raise RuntimeError('VM operation timed out: ' + command[0]) from None
    if p.returncode:
        # Never include a bootstrap token, SSH key or kubeconfig in error output.
        detail = re.sub(r'\b[a-z0-9]{6}\.[a-z0-9]{16}\b', '[bootstrap token]',
                        p.stderr.decode(errors='replace')[-1800:])
        raise RuntimeError('VM operation failed: ' + command[0] + ' (exit ' + str(p.returncode) + '): ' + detail)
    return p.stdout


def ssh(node, args, timeout=30, data=None):
    nodes = json.loads((ROOT / 'vms.json').read_text())
    assert node in (CLUSTER + '-worker', CLUSTER + '-worker2')
    return run(['ssh', '-i', str(ROOT / 'vm-key'), '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
                '-o', 'StrictHostKeyChecking=accept-new', '-o', 'UserKnownHostsFile=' + str(ROOT / 'vm-known-hosts'),
                'ubuntu@' + nodes[node]['ip'], 'sudo -- ' + shlex.join(args)], timeout, data)


def assert_owned(node):
    nodes = json.loads((ROOT / 'vms.json').read_text())
    assert ssh(node, ['cat', '/etc/hnn-heartbeat-e2e-id']).decode().strip() == nodes[node]['nonce']
    assert ssh(node, ['hostname']).decode().strip() == node


def wait_for_ssh(node):
    until = time.monotonic() + 300
    while time.monotonic() < until:
        try:
            assert_owned(node)
            return
        except (RuntimeError, subprocess.TimeoutExpired):
            time.sleep(3)
    raise RuntimeError('VM did not finish booting: ' + node)


def bootstrap(node):
    wait_for_ssh(node)
    ssh(node, ['cloud-init', 'status', '--wait'], timeout=360)
    control_plane = json.loads(run(['docker', 'inspect', CP]))[0]
    address = str(ipaddress.ip_address(control_plane['NetworkSettings']['Networks']['kind']['IPAddress']))
    # kubeadm's cluster-info uses the Docker node hostname. Native VMs do not use
    # Docker's embedded DNS, so keep that same endpoint resolvable inside each VM.
    ssh(node, ['sh', '-c', 'cat >> /etc/hosts'], data=(address + ' ' + CP + '\n').encode())
    payload = (ROOT / 'worker-binaries.tar.gz').read_bytes()
    ssh(node, ['tar', '-xzf', '-', '-C', '/'], timeout=90, data=payload)
    setup = r'''set -eu
mkdir -p /etc/containerd /etc/kubernetes/manifests /var/lib/kubelet
/usr/local/bin/containerd config default > /etc/containerd/config.toml
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
cat > /etc/systemd/system/containerd.service <<'UNIT'
[Unit]
After=network-online.target
[Service]
ExecStart=/usr/local/bin/containerd
Restart=always
Delegate=yes
KillMode=process
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/kubelet.service <<'UNIT'
[Unit]
After=containerd.service
Requires=containerd.service
[Service]
EnvironmentFile=-/var/lib/kubelet/kubeadm-flags.env
ExecStart=/usr/bin/kubelet --bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf --config=/var/lib/kubelet/config.yaml --resolv-conf=/run/systemd/resolve/resolv.conf $KUBELET_KUBEADM_ARGS
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT
modprobe overlay
modprobe br_netfilter
modprobe iscsi_tcp
sysctl -w net.ipv4.ip_forward=1 net.bridge.bridge-nf-call-iptables=1
swapoff -a
systemctl daemon-reload
systemctl enable --now containerd kubelet iscsid
'''
    ssh(node, ['bash', '-se'], timeout=60, data=setup.encode())
    join = run(['docker', 'exec', CP, 'kubeadm', 'token', 'create', '--ttl=30m', '--print-join-command']).decode().strip()
    token = shlex.split(join)[shlex.split(join).index('--token') + 1]
    print('::add-mask::' + token, flush=True)
    ssh(node, shlex.split(join) + ['--node-name', node, '--cri-socket', 'unix:///run/containerd/containerd.sock'], timeout=180)
    print(json.dumps({'vm': node, 'joined': True}), flush=True)


def create():
    import yaml
    assert not (ROOT / 'vms.json').exists()
    assert Path('/dev/kvm').exists(), 'This E2E requires a runner with KVM; do not silently use fake storage'
    network = json.loads(run(['docker', 'network', 'inspect', 'kind']))[0]
    config = next(c for c in network['IPAM']['Config'] if ':' not in c['Subnet'])
    subnet = ipaddress.ip_network(config['Subnet'])
    assert subnet.prefixlen <= 24 and subnet.is_private
    bridge = network['Options'].get('com.docker.network.bridge.name') or 'br-' + network['Id'][:12]
    key = ROOT / 'vm-key'
    run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)])
    image = ROOT / 'ubuntu.img'
    base = 'https://cloud-images.ubuntu.com/noble/current/'
    sums = urllib.request.urlopen(base + 'SHA256SUMS', timeout=20).read().decode()
    digest = next(s.split()[0] for s in sums.splitlines() if s.split()[-1].lstrip('*') == 'noble-server-cloudimg-amd64.img')
    run(['curl', '--fail', '--location', '--silent', '--show-error', '--connect-timeout', '15', '--max-time', '180',
         '--retry', '2', base + 'noble-server-cloudimg-amd64.img', '-o', str(image)], timeout=400)
    assert hashlib.sha256(image.read_bytes()).hexdigest() == digest
    (ROOT / 'results' / 'vm-image.json').write_text(json.dumps({'image': base, 'sha256': digest}))
    # Reuse the exact Kubernetes, containerd, runc and CNI binaries from the pinned kind image.
    binaries = ['usr/local/bin/containerd', 'usr/local/bin/containerd-shim-runc-v2', 'usr/local/bin/ctr',
                'usr/local/sbin/runc', 'usr/bin/kubelet', 'usr/bin/kubeadm', 'opt/cni/bin']
    (ROOT / 'worker-binaries.tar.gz').write_bytes(run(['docker', 'exec', CP, 'tar', '-czf', '-', '-C', '/', *binaries], timeout=60))
    nodes = {CLUSTER + '-' + suffix: {'ip': str(subnet.network_address + 200 + i), 'nonce': secrets.token_hex(16),
                                    'tap': 'hnn-fault' + str(i)} for i, suffix in enumerate(['worker', 'worker2'])}
    (ROOT / 'vms.json').write_text(json.dumps(nodes))
    for node, info in nodes.items():
        user = {'hostname': node, 'ssh_pwauth': False, 'ssh_authorized_keys': [key.with_suffix('.pub').read_text().strip()],
                'package_update': True, 'packages': ['open-iscsi', 'nfs-common', 'conntrack', 'socat', 'iptables', 'libseccomp2'],
                'write_files': [{'path': '/etc/hnn-heartbeat-e2e-id', 'permissions': '0600', 'content': info['nonce']}],
                'runcmd': [['systemctl', 'enable', '--now', 'iscsid']]}
        (ROOT / (node + '.user')).write_text('#cloud-config\n' + yaml.safe_dump(user))
        (ROOT / (node + '.meta')).write_text(yaml.safe_dump({'instance-id': node, 'local-hostname': node}))
        mac = '52:54:00:ab:cd:' + ('11' if node.endswith('worker') else '12')
        net = {'version': 2, 'ethernets': {'eth0': {'match': {'macaddress': mac}, 'set-name': 'eth0',
               'addresses': [info['ip'] + '/' + str(subnet.prefixlen)], 'routes': [{'to': 'default', 'via': config['Gateway']}],
               'nameservers': {'addresses': ['1.1.1.1', '8.8.8.8']}}}}
        (ROOT / (node + '.net')).write_text(yaml.safe_dump(net))
        run(['cloud-localds', '--network-config=' + str(ROOT / (node + '.net')), str(ROOT / (node + '.seed')),
             str(ROOT / (node + '.user')), str(ROOT / (node + '.meta'))])
        run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(image), str(ROOT / (node + '.disk')), '16G'])
        run(['sudo', 'ip', 'tuntap', 'add', info['tap'], 'mode', 'tap'])
        run(['sudo', 'ip', 'link', 'set', info['tap'], 'master', bridge])
        run(['sudo', 'ip', 'link', 'set', info['tap'], 'up'])
        run(['sudo', 'qemu-system-x86_64', '-name', node, '-accel', 'kvm', '-cpu', 'host', '-m', '2304', '-smp', '2',
             '-drive', 'file=' + str(ROOT / (node + '.disk')) + ',if=virtio,format=qcow2',
             '-drive', 'file=' + str(ROOT / (node + '.seed')) + ',if=virtio,format=raw,readonly=on',
             '-netdev', 'tap,id=n0,ifname=' + info['tap'] + ',script=no,downscript=no',
             '-device', 'virtio-net-pci,netdev=n0,mac=' + mac, '-display', 'none', '-daemonize',
             '-serial', 'file:' + str(ROOT / 'results' / (node + '.serial.log')), '-pidfile', str(ROOT / (node + '.pid'))])
        run(['sudo', 'chown', str(os.getuid()) + ':' + str(os.getgid()),
             str(ROOT / 'results' / (node + '.serial.log')), str(ROOT / (node + '.pid'))])
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(bootstrap, nodes))


def destroy():
    if not (ROOT / 'vms.json').exists():
        return
    for node, info in json.loads((ROOT / 'vms.json').read_text()).items():
        assert node in (CLUSTER + '-worker', CLUSTER + '-worker2')
        pidfile = ROOT / (node + '.pid')
        if pidfile.exists():
            pid = int(pidfile.read_text())
            cmdline = Path('/proc/' + str(pid) + '/cmdline')
            if cmdline.exists():
                command = cmdline.read_bytes().split(b'\0')
                assert b'qemu-system-x86_64' in Path(command[0].decode()).name.encode()
                assert node.encode() in command and any(str(ROOT).encode() in arg for arg in command)
                run(['sudo', 'kill', '-TERM', str(pid)])
        run(['sudo', 'ip', 'link', 'delete', info['tap']])


if __name__ == '__main__':
    assert os.environ.get('GITHUB_ACTIONS') == 'true'
    assert os.environ.get('HNN_FAULT_E2E') == 'isolated-vms-only'
    assert os.environ.get('KUBECONFIG') == str(ROOT / 'kubeconfig')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['create', 'destroy'])
    args = parser.parse_args()
    create() if args.operation == 'create' else destroy()
