# ipars-packet-flow-ebpf

This crate builds the packet-flow eBPF object consumed by:

```bash
iparsd agent \
  --packet-flow-detector ebpf-ringbuf \
  --packet-flow-ebpf-object-path target/ebpf/ipars-packet-flow.bpf.o \
  --packet-flow-ebpf-attach ipars_sys_enter_connect:syscalls:sys_enter_connect \
  --packet-flow-ebpf-attach ipars_sys_enter_sendto:syscalls:sys_enter_sendto
```

Build it from the repository root with:

```bash
scripts/build-ebpf.sh
```

The object exports the `IPARS_PACKET_FLOWS` ring buffer and writes the shared ipars packet-flow ABI v1 event from outbound `connect(2)` and `sendto(2)` syscall tracepoints.
