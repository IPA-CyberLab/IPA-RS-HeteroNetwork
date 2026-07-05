#![no_std]
#![no_main]

#[allow(dead_code)]
#[path = "../../../crates/ipars-types/src/ebpf.rs"]
mod ipars_ebpf_abi;

use aya_ebpf::{
    helpers::bpf_probe_read_user,
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use ipars_ebpf_abi::{
    PacketFlowEvent, PacketFlowEventFields, PACKET_FLOW_IP_FAMILY_IPV4, PACKET_FLOW_IP_FAMILY_IPV6,
    PACKET_FLOW_PROTOCOL_UNKNOWN, PACKET_FLOW_TCP_STATE_UNKNOWN,
};

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const SYSCALL_TRACEPOINT_ARGS_OFFSET: usize = 16;
const SYSCALL_TRACEPOINT_ARG_SIZE: usize = 8;
const CONNECT_SOCKADDR_ARG: usize = 1;
const SENDTO_SOCKADDR_ARG: usize = 4;
const RINGBUF_BYTES: u32 = 256 * 1024;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn {
    family: u16,
    port_be: [u8; 2],
    addr: [u8; 4],
    zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn6 {
    family: u16,
    port_be: [u8; 2],
    flowinfo: u32,
    addr: [u8; 16],
    scope_id: u32,
}

#[map]
pub static IPARS_PACKET_FLOWS: RingBuf = RingBuf::with_byte_size(RINGBUF_BYTES, 0);

#[tracepoint]
pub fn ipars_sys_enter_connect(ctx: TracePointContext) -> u32 {
    emit_sockaddr_arg(&ctx, CONNECT_SOCKADDR_ARG);
    0
}

#[tracepoint]
pub fn ipars_sys_enter_sendto(ctx: TracePointContext) -> u32 {
    emit_sockaddr_arg(&ctx, SENDTO_SOCKADDR_ARG);
    0
}

fn emit_sockaddr_arg(ctx: &TracePointContext, arg_index: usize) {
    let Ok(sockaddr_addr) = read_syscall_arg(ctx, arg_index) else {
        return;
    };
    if sockaddr_addr == 0 {
        return;
    }

    let sockaddr = sockaddr_addr as *const u8;
    let Ok(family) = (unsafe { bpf_probe_read_user(sockaddr as *const u16) }) else {
        return;
    };

    match family {
        AF_INET => emit_sockaddr_in(sockaddr as *const SockAddrIn),
        AF_INET6 => emit_sockaddr_in6(sockaddr as *const SockAddrIn6),
        _ => {}
    }
}

fn read_syscall_arg(ctx: &TracePointContext, arg_index: usize) -> Result<u64, i64> {
    let offset = SYSCALL_TRACEPOINT_ARGS_OFFSET + arg_index * SYSCALL_TRACEPOINT_ARG_SIZE;
    unsafe { ctx.read_at::<u64>(offset) }
}

fn emit_sockaddr_in(sockaddr: *const SockAddrIn) {
    let Ok(sockaddr) = (unsafe { bpf_probe_read_user(sockaddr) }) else {
        return;
    };
    let mut destination = [0_u8; 16];
    destination[..4].copy_from_slice(&sockaddr.addr);
    emit_event(PacketFlowEvent::new(PacketFlowEventFields {
        ip_family: PACKET_FLOW_IP_FAMILY_IPV4,
        protocol: PACKET_FLOW_PROTOCOL_UNKNOWN,
        tcp_state: PACKET_FLOW_TCP_STATE_UNKNOWN,
        conntrack_status: 0,
        source_port_be: [0, 0],
        destination_port_be: sockaddr.port_be,
        source: [0; 16],
        destination,
    }));
}

fn emit_sockaddr_in6(sockaddr: *const SockAddrIn6) {
    let Ok(sockaddr) = (unsafe { bpf_probe_read_user(sockaddr) }) else {
        return;
    };
    emit_event(PacketFlowEvent::new(PacketFlowEventFields {
        ip_family: PACKET_FLOW_IP_FAMILY_IPV6,
        protocol: PACKET_FLOW_PROTOCOL_UNKNOWN,
        tcp_state: PACKET_FLOW_TCP_STATE_UNKNOWN,
        conntrack_status: 0,
        source_port_be: [0, 0],
        destination_port_be: sockaddr.port_be,
        source: [0; 16],
        destination: sockaddr.addr,
    }));
}

fn emit_event(event: PacketFlowEvent) {
    let _ = IPARS_PACKET_FLOWS.output(&event, 0);
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
