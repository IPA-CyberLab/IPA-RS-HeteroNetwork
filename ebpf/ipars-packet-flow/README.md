# ipars-packet-flow-ebpf

This crate builds the packet-flow eBPF object consumed by:

```bash
iparsd agent \
  --packet-flow-detector ebpf-ringbuf \
  --packet-flow-ebpf-object-path target/ebpf/ipars-packet-flow.bpf.o \
  --packet-flow-ebpf-cgroup-path /sys/fs/cgroup/system.slice/ipars-agent.service \
  --packet-flow-ebpf-cgroup-attach ipars_cgroup_connect4 \
  --packet-flow-ebpf-cgroup-attach ipars_cgroup_connect6 \
  --packet-flow-ebpf-cgroup-attach ipars_cgroup_sendmsg4 \
  --packet-flow-ebpf-cgroup-attach ipars_cgroup_sendmsg6
```

The selected cgroup must contain the agent and the workloads whose outbound socket activity should
activate lazy peers. Syscall tracepoints remain available as a lower-fidelity fallback:

```bash
iparsd agent \
  --packet-flow-detector ebpf-ringbuf \
  --packet-flow-ebpf-object-path target/ebpf/ipars-packet-flow.bpf.o \
  --packet-flow-ebpf-attach ipars_sys_enter_connect:syscalls:sys_enter_connect \
  --packet-flow-ebpf-attach ipars_sys_enter_sendto:syscalls:sys_enter_sendto \
  --packet-flow-ebpf-attach ipars_sys_enter_sendmsg:syscalls:sys_enter_sendmsg
```

Build it from the repository root with:

```bash
rustup toolchain install nightly-2026-07-05 --profile minimal --component rust-src
cargo install bpf-linker --version 0.10.3 --locked
scripts/build-ebpf.sh
```

The build rejects a different `bpf-linker` version by default. `IPARS_EBPF_TOOLCHAIN`, `IPARS_EBPF_BPF_LINKER_VERSION`, `IPARS_EBPF_TARGET`, and `IPARS_EBPF_PROFILE` are explicit overrides for controlled toolchain migrations.

The object exports the `IPARS_PACKET_FLOWS` ring buffer and writes the shared ipars packet-flow ABI v1 event. The cgroup socket-address programs emit kernel-provided IPv4/IPv6 destination, protocol, bound source address, and source port metadata for TCP `connect(2)` and UDP send-message hooks. They always return `1`, so observation never rejects or rewrites application traffic. This mode requires cgroup v2, a kernel with `bpf_sock_addr.sk` support (Linux 5.3 or newer), `CAP_BPF`, and `CAP_NET_ADMIN` or equivalent privilege.

The tracepoint programs check the supplied sockaddr length before reading IPv4 or IPv6 address data. Syscall tracepoints expose the destination sockaddr but not a trustworthy socket protocol, so fallback events retain the network-order destination port while reporting the protocol as unknown. The typed userspace model accepts that partial observation while still rejecting ports paired with known non-port protocols. Tracepoint mode additionally requires `CAP_PERFMON` or `CAP_SYS_ADMIN` and mounted tracefs event metadata.

Run the real attach and ring-buffer event gate on a privileged Linux host with tracefs:

```bash
sudo env PATH="$PATH" CARGO="$(command -v cargo)" IPARS_RUN_EBPF_ATTACH_TESTS=1 IPARS_EBPF_OBJECT_PATH="$PWD/target/ebpf/ipars-packet-flow.bpf.o" cargo test --locked -p ipars-daemon ebpf_ringbuf_privileged_attach_reads_sendto_event
sudo env PATH="$PATH" CARGO="$(command -v cargo)" IPARS_RUN_EBPF_ATTACH_TESTS=1 IPARS_EBPF_OBJECT_PATH="$PWD/target/ebpf/ipars-packet-flow.bpf.o" cargo test --locked -p ipars-daemon ebpf_ringbuf_privileged_cgroup_hooks_read_connect_and_sendmsg_events
```
