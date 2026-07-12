# ipars-packet-flow-ebpf

This crate builds the packet-flow eBPF object consumed by:

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

The object exports the `IPARS_PACKET_FLOWS` ring buffer and writes the shared ipars packet-flow ABI v1 event from outbound `connect(2)`, `sendto(2)`, and destination-addressed `sendmsg(2)` syscall tracepoints. It checks the supplied sockaddr length before reading IPv4 or IPv6 address data. Syscall tracepoints expose the destination sockaddr but not a trustworthy socket protocol, so these events retain the network-order destination port while reporting the protocol as unknown; the typed userspace model accepts that partial observation while still rejecting ports paired with known non-port protocols.

Run the real attach and ring-buffer event gate on a privileged Linux host with tracefs:

```bash
sudo env PATH="$PATH" CARGO="$(command -v cargo)" IPARS_RUN_EBPF_ATTACH_TESTS=1 IPARS_EBPF_OBJECT_PATH="$PWD/target/ebpf/ipars-packet-flow.bpf.o" cargo test --locked -p ipars-daemon ebpf_ringbuf_privileged_attach_reads_sendto_event
```
