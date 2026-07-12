#![no_std]
#![no_main]

#[allow(dead_code)]
#[path = "../../../crates/ipars-types/src/ebpf.rs"]
mod ipars_ebpf_abi;

use aya_ebpf::{
    bindings::{
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB, BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,
        BPF_SOCK_OPS_STATE_CB, BPF_SOCK_OPS_STATE_CB_FLAG, BPF_SOCK_OPS_TCP_CONNECT_CB,
        BPF_TCP_CLOSE, BPF_TCP_CLOSE_WAIT, BPF_TCP_CLOSING, BPF_TCP_ESTABLISHED, BPF_TCP_FIN_WAIT1,
        BPF_TCP_FIN_WAIT2, BPF_TCP_LAST_ACK, BPF_TCP_LISTEN, BPF_TCP_NEW_SYN_RECV,
        BPF_TCP_SYN_RECV, BPF_TCP_SYN_SENT, BPF_TCP_TIME_WAIT,
    },
    helpers::bpf_probe_read_user,
    macros::{cgroup_sock_addr, map, sock_ops, tracepoint},
    maps::RingBuf,
    programs::{SockAddrContext, SockOpsContext, TracePointContext},
};
use ipars_ebpf_abi::{
    PacketFlowEvent, PacketFlowEventFields, PACKET_FLOW_IP_FAMILY_IPV4, PACKET_FLOW_IP_FAMILY_IPV6,
    PACKET_FLOW_PROTOCOL_AH, PACKET_FLOW_PROTOCOL_ESP, PACKET_FLOW_PROTOCOL_GRE,
    PACKET_FLOW_PROTOCOL_ICMP, PACKET_FLOW_PROTOCOL_ICMPV6, PACKET_FLOW_PROTOCOL_IPIP,
    PACKET_FLOW_PROTOCOL_IPV6_ENCAP, PACKET_FLOW_PROTOCOL_SCTP, PACKET_FLOW_PROTOCOL_TCP,
    PACKET_FLOW_PROTOCOL_UDP, PACKET_FLOW_PROTOCOL_UNKNOWN, PACKET_FLOW_TCP_STATE_CLOSE,
    PACKET_FLOW_TCP_STATE_CLOSE_WAIT, PACKET_FLOW_TCP_STATE_ESTABLISHED,
    PACKET_FLOW_TCP_STATE_FIN_WAIT, PACKET_FLOW_TCP_STATE_LAST_ACK, PACKET_FLOW_TCP_STATE_LISTEN,
    PACKET_FLOW_TCP_STATE_SYN_RECV, PACKET_FLOW_TCP_STATE_SYN_SENT,
    PACKET_FLOW_TCP_STATE_TIME_WAIT, PACKET_FLOW_TCP_STATE_UNKNOWN,
};

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const SYSCALL_TRACEPOINT_ARGS_OFFSET: usize = 16;
const SYSCALL_TRACEPOINT_ARG_SIZE: usize = 8;
const CONNECT_SOCKADDR_ARG: usize = 1;
const CONNECT_SOCKADDR_LEN_ARG: usize = 2;
const SENDTO_SOCKADDR_ARG: usize = 4;
const SENDTO_SOCKADDR_LEN_ARG: usize = 5;
const SENDMSG_MSGHDR_ARG: usize = 1;
const SOCKADDR_IN_LEN: u32 = 16;
const SOCKADDR_IN6_LEN: u32 = 28;
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

#[repr(C)]
#[derive(Clone, Copy)]
struct UserMsghdr {
    name: *const u8,
    namelen: u32,
    _padding: u32,
}

#[map]
pub static IPARS_PACKET_FLOWS: RingBuf = RingBuf::with_byte_size(RINGBUF_BYTES, 0);

#[tracepoint]
pub fn ipars_sys_enter_connect(ctx: TracePointContext) -> u32 {
    emit_sockaddr_arg(&ctx, CONNECT_SOCKADDR_ARG, CONNECT_SOCKADDR_LEN_ARG);
    0
}

#[tracepoint]
pub fn ipars_sys_enter_sendto(ctx: TracePointContext) -> u32 {
    emit_sockaddr_arg(&ctx, SENDTO_SOCKADDR_ARG, SENDTO_SOCKADDR_LEN_ARG);
    0
}

#[tracepoint]
pub fn ipars_sys_enter_sendmsg(ctx: TracePointContext) -> u32 {
    emit_msghdr_name_arg(&ctx, SENDMSG_MSGHDR_ARG);
    0
}

#[cgroup_sock_addr(connect4)]
pub fn ipars_cgroup_connect4(ctx: SockAddrContext) -> i32 {
    emit_cgroup_ipv4(&ctx, false);
    1
}

#[cgroup_sock_addr(connect6)]
pub fn ipars_cgroup_connect6(ctx: SockAddrContext) -> i32 {
    emit_cgroup_ipv6(&ctx, false);
    1
}

#[cgroup_sock_addr(sendmsg4)]
pub fn ipars_cgroup_sendmsg4(ctx: SockAddrContext) -> i32 {
    emit_cgroup_ipv4(&ctx, true);
    1
}

#[cgroup_sock_addr(sendmsg6)]
pub fn ipars_cgroup_sendmsg6(ctx: SockAddrContext) -> i32 {
    emit_cgroup_ipv6(&ctx, true);
    1
}

#[sock_ops]
pub fn ipars_cgroup_sockops(ctx: SockOpsContext) -> u32 {
    match ctx.op() {
        BPF_SOCK_OPS_TCP_CONNECT_CB
        | BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB
        | BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB => enable_sockops_state_callbacks(&ctx),
        BPF_SOCK_OPS_STATE_CB => {
            let state = sockops_tcp_state(ctx.arg(1));
            if state != PACKET_FLOW_TCP_STATE_UNKNOWN {
                emit_sockops_tcp_event(&ctx, state);
            }
        }
        _ => {}
    }
    0
}

#[inline(always)]
fn enable_sockops_state_callbacks(ctx: &SockOpsContext) {
    let flags = ctx.cb_flags() | BPF_SOCK_OPS_STATE_CB_FLAG;
    let _ = ctx.set_cb_flags(flags as i32);
}

#[inline(always)]
fn emit_sockops_tcp_event(ctx: &SockOpsContext, tcp_state: u8) {
    // Sockops exposes the network-order 16-bit remote port in the upper half.
    let destination_port_be = ((ctx.remote_port() >> 16) as u16).to_ne_bytes();
    if destination_port_be == [0; 2] {
        return;
    }
    let source_port_be = (ctx.local_port() as u16).to_be_bytes();
    match ctx.family() as u16 {
        AF_INET => {
            let remote = ctx.remote_ip4().to_ne_bytes();
            if remote == [0; 4] {
                return;
            }
            let mut source = [0_u8; 16];
            source[..4].copy_from_slice(&ctx.local_ip4().to_ne_bytes());
            let mut destination = [0_u8; 16];
            destination[..4].copy_from_slice(&remote);
            emit_event(PacketFlowEvent::new(PacketFlowEventFields {
                ip_family: PACKET_FLOW_IP_FAMILY_IPV4,
                protocol: PACKET_FLOW_PROTOCOL_TCP,
                tcp_state,
                conntrack_status: 0,
                source_port_be,
                destination_port_be,
                source,
                destination,
            }));
        }
        AF_INET6 => {
            let destination = sockops_remote_ipv6(ctx);
            if destination == [0; 16] {
                return;
            }
            emit_event(PacketFlowEvent::new(PacketFlowEventFields {
                ip_family: PACKET_FLOW_IP_FAMILY_IPV6,
                protocol: PACKET_FLOW_PROTOCOL_TCP,
                tcp_state,
                conntrack_status: 0,
                source_port_be,
                destination_port_be,
                source: sockops_local_ipv6(ctx),
                destination,
            }));
        }
        _ => {}
    }
}

#[inline(always)]
fn sockops_remote_ipv6(ctx: &SockOpsContext) -> [u8; 16] {
    unsafe {
        network_ipv6_bytes([
            core::ptr::read_volatile(core::ptr::addr_of!((*ctx.ops).remote_ip6[0])),
            core::ptr::read_volatile(core::ptr::addr_of!((*ctx.ops).remote_ip6[1])),
            core::ptr::read_volatile(core::ptr::addr_of!((*ctx.ops).remote_ip6[2])),
            core::ptr::read_volatile(core::ptr::addr_of!((*ctx.ops).remote_ip6[3])),
        ])
    }
}

#[inline(always)]
fn sockops_local_ipv6(ctx: &SockOpsContext) -> [u8; 16] {
    unsafe {
        network_ipv6_bytes([
            core::ptr::read_volatile(core::ptr::addr_of!((*ctx.ops).local_ip6[0])),
            core::ptr::read_volatile(core::ptr::addr_of!((*ctx.ops).local_ip6[1])),
            core::ptr::read_volatile(core::ptr::addr_of!((*ctx.ops).local_ip6[2])),
            core::ptr::read_volatile(core::ptr::addr_of!((*ctx.ops).local_ip6[3])),
        ])
    }
}

#[inline(always)]
fn sockops_tcp_state(state: u32) -> u8 {
    match state {
        BPF_TCP_SYN_SENT => PACKET_FLOW_TCP_STATE_SYN_SENT,
        BPF_TCP_SYN_RECV | BPF_TCP_NEW_SYN_RECV => PACKET_FLOW_TCP_STATE_SYN_RECV,
        BPF_TCP_ESTABLISHED => PACKET_FLOW_TCP_STATE_ESTABLISHED,
        BPF_TCP_FIN_WAIT1 | BPF_TCP_FIN_WAIT2 | BPF_TCP_CLOSING => PACKET_FLOW_TCP_STATE_FIN_WAIT,
        BPF_TCP_TIME_WAIT => PACKET_FLOW_TCP_STATE_TIME_WAIT,
        BPF_TCP_CLOSE => PACKET_FLOW_TCP_STATE_CLOSE,
        BPF_TCP_CLOSE_WAIT => PACKET_FLOW_TCP_STATE_CLOSE_WAIT,
        BPF_TCP_LAST_ACK => PACKET_FLOW_TCP_STATE_LAST_ACK,
        BPF_TCP_LISTEN => PACKET_FLOW_TCP_STATE_LISTEN,
        _ => PACKET_FLOW_TCP_STATE_UNKNOWN,
    }
}

#[inline(always)]
fn emit_cgroup_ipv4(ctx: &SockAddrContext, use_message_source: bool) {
    let sock_addr = unsafe { &*ctx.sock_addr };
    let mut destination = [0_u8; 16];
    destination[..4].copy_from_slice(&sock_addr.user_ip4.to_ne_bytes());
    let (socket_source, source_port_be) = socket_source_ipv4(ctx);
    let message_source = sock_addr.msg_src_ip4.to_ne_bytes();
    let source_ipv4 = if use_message_source && message_source != [0; 4] {
        message_source
    } else {
        socket_source
    };
    let mut source = [0_u8; 16];
    source[..4].copy_from_slice(&source_ipv4);
    emit_event(PacketFlowEvent::new(PacketFlowEventFields {
        ip_family: PACKET_FLOW_IP_FAMILY_IPV4,
        protocol: supported_protocol(sock_addr.protocol),
        tcp_state: PACKET_FLOW_TCP_STATE_UNKNOWN,
        conntrack_status: 0,
        source_port_be,
        destination_port_be: (sock_addr.user_port as u16).to_ne_bytes(),
        source,
        destination,
    }));
}

#[inline(always)]
fn emit_cgroup_ipv6(ctx: &SockAddrContext, use_message_source: bool) {
    let sock_addr = unsafe { &*ctx.sock_addr };
    let socket_source = socket_source_ipv6(ctx);
    let message_source = network_ipv6_bytes(sock_addr.msg_src_ip6);
    let source = if use_message_source && message_source != [0; 16] {
        message_source
    } else {
        socket_source.0
    };
    emit_event(PacketFlowEvent::new(PacketFlowEventFields {
        ip_family: PACKET_FLOW_IP_FAMILY_IPV6,
        protocol: supported_protocol(sock_addr.protocol),
        tcp_state: PACKET_FLOW_TCP_STATE_UNKNOWN,
        conntrack_status: 0,
        source_port_be: socket_source.1,
        destination_port_be: (sock_addr.user_port as u16).to_ne_bytes(),
        source,
        destination: network_ipv6_bytes(sock_addr.user_ip6),
    }));
}

#[inline(always)]
fn socket_source_ipv4(ctx: &SockAddrContext) -> ([u8; 4], [u8; 2]) {
    let socket = unsafe { (*ctx.sock_addr).__bindgen_anon_1.sk };
    if socket.is_null() {
        return ([0; 4], [0; 2]);
    }
    unsafe {
        (
            (*socket).src_ip4.to_ne_bytes(),
            ((*socket).src_port as u16).to_be_bytes(),
        )
    }
}

#[inline(always)]
fn socket_source_ipv6(ctx: &SockAddrContext) -> ([u8; 16], [u8; 2]) {
    let socket = unsafe { (*ctx.sock_addr).__bindgen_anon_1.sk };
    if socket.is_null() {
        return ([0; 16], [0; 2]);
    }
    unsafe {
        (
            network_ipv6_bytes((*socket).src_ip6),
            ((*socket).src_port as u16).to_be_bytes(),
        )
    }
}

#[inline(always)]
fn network_ipv6_bytes(words: [u32; 4]) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    bytes[0..4].copy_from_slice(&words[0].to_ne_bytes());
    bytes[4..8].copy_from_slice(&words[1].to_ne_bytes());
    bytes[8..12].copy_from_slice(&words[2].to_ne_bytes());
    bytes[12..16].copy_from_slice(&words[3].to_ne_bytes());
    bytes
}

#[inline(always)]
fn supported_protocol(protocol: u32) -> u8 {
    match protocol {
        value if value == PACKET_FLOW_PROTOCOL_ICMP as u32 => PACKET_FLOW_PROTOCOL_ICMP,
        value if value == PACKET_FLOW_PROTOCOL_IPIP as u32 => PACKET_FLOW_PROTOCOL_IPIP,
        value if value == PACKET_FLOW_PROTOCOL_TCP as u32 => PACKET_FLOW_PROTOCOL_TCP,
        value if value == PACKET_FLOW_PROTOCOL_UDP as u32 => PACKET_FLOW_PROTOCOL_UDP,
        value if value == PACKET_FLOW_PROTOCOL_IPV6_ENCAP as u32 => PACKET_FLOW_PROTOCOL_IPV6_ENCAP,
        value if value == PACKET_FLOW_PROTOCOL_GRE as u32 => PACKET_FLOW_PROTOCOL_GRE,
        value if value == PACKET_FLOW_PROTOCOL_ESP as u32 => PACKET_FLOW_PROTOCOL_ESP,
        value if value == PACKET_FLOW_PROTOCOL_AH as u32 => PACKET_FLOW_PROTOCOL_AH,
        value if value == PACKET_FLOW_PROTOCOL_ICMPV6 as u32 => PACKET_FLOW_PROTOCOL_ICMPV6,
        value if value == PACKET_FLOW_PROTOCOL_SCTP as u32 => PACKET_FLOW_PROTOCOL_SCTP,
        _ => PACKET_FLOW_PROTOCOL_UNKNOWN,
    }
}

fn emit_sockaddr_arg(ctx: &TracePointContext, sockaddr_arg_index: usize, len_arg_index: usize) {
    let Ok(sockaddr_addr) = read_syscall_arg(ctx, sockaddr_arg_index) else {
        return;
    };
    let Ok(sockaddr_len) = read_syscall_arg(ctx, len_arg_index) else {
        return;
    };
    emit_sockaddr(
        sockaddr_addr as *const u8,
        sockaddr_len.min(u64::from(u32::MAX)) as u32,
    );
}

fn emit_msghdr_name_arg(ctx: &TracePointContext, arg_index: usize) {
    let Ok(msghdr_addr) = read_syscall_arg(ctx, arg_index) else {
        return;
    };
    if msghdr_addr == 0 {
        return;
    }
    let Ok(msghdr) = (unsafe { bpf_probe_read_user(msghdr_addr as *const UserMsghdr) }) else {
        return;
    };
    emit_sockaddr(msghdr.name, msghdr.namelen);
}

fn emit_sockaddr(sockaddr: *const u8, sockaddr_len: u32) {
    if sockaddr.is_null() || sockaddr_len < 2 {
        return;
    }
    let Ok(family) = (unsafe { bpf_probe_read_user(sockaddr as *const u16) }) else {
        return;
    };

    match family {
        AF_INET if sockaddr_len >= SOCKADDR_IN_LEN => {
            emit_sockaddr_in(sockaddr as *const SockAddrIn)
        }
        AF_INET6 if sockaddr_len >= SOCKADDR_IN6_LEN => {
            emit_sockaddr_in6(sockaddr as *const SockAddrIn6)
        }
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
