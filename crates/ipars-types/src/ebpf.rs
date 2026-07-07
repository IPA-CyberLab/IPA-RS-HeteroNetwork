use core::fmt;

pub const PACKET_FLOW_EVENT_VERSION: u8 = 1;
pub const PACKET_FLOW_EVENT_LEN: usize = 48;
pub const PACKET_FLOW_RINGBUF_MAP: &str = "IPARS_PACKET_FLOWS";

pub const PACKET_FLOW_IP_FAMILY_IPV4: u8 = 4;
pub const PACKET_FLOW_IP_FAMILY_IPV6: u8 = 6;

pub const PACKET_FLOW_PROTOCOL_UNKNOWN: u8 = 0;
pub const PACKET_FLOW_PROTOCOL_ICMP: u8 = 1;
pub const PACKET_FLOW_PROTOCOL_IPIP: u8 = 4;
pub const PACKET_FLOW_PROTOCOL_TCP: u8 = 6;
pub const PACKET_FLOW_PROTOCOL_UDP: u8 = 17;
pub const PACKET_FLOW_PROTOCOL_IPV6_ENCAP: u8 = 41;
pub const PACKET_FLOW_PROTOCOL_GRE: u8 = 47;
pub const PACKET_FLOW_PROTOCOL_ESP: u8 = 50;
pub const PACKET_FLOW_PROTOCOL_AH: u8 = 51;
pub const PACKET_FLOW_PROTOCOL_ICMPV6: u8 = 58;
pub const PACKET_FLOW_PROTOCOL_SCTP: u8 = 132;

pub const PACKET_FLOW_TCP_STATE_UNKNOWN: u8 = 0;
pub const PACKET_FLOW_TCP_STATE_SYN_SENT: u8 = 1;
pub const PACKET_FLOW_TCP_STATE_SYN_RECV: u8 = 2;
pub const PACKET_FLOW_TCP_STATE_ESTABLISHED: u8 = 3;
pub const PACKET_FLOW_TCP_STATE_FIN_WAIT: u8 = 4;
pub const PACKET_FLOW_TCP_STATE_TIME_WAIT: u8 = 5;
pub const PACKET_FLOW_TCP_STATE_CLOSE: u8 = 6;
pub const PACKET_FLOW_TCP_STATE_CLOSE_WAIT: u8 = 7;
pub const PACKET_FLOW_TCP_STATE_LAST_ACK: u8 = 8;
pub const PACKET_FLOW_TCP_STATE_LISTEN: u8 = 9;
pub const PACKET_FLOW_TCP_STATE_SYN_SENT2: u8 = 10;

pub const PACKET_FLOW_CONNTRACK_UNREPLIED: u8 = 0x01;
pub const PACKET_FLOW_CONNTRACK_ASSURED: u8 = 0x02;

#[repr(C, align(8))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketFlowEvent {
    pub version: u8,
    pub ip_family: u8,
    pub protocol: u8,
    pub tcp_state: u8,
    pub conntrack_status: u8,
    pub flags: u8,
    pub source_port_be: [u8; 2],
    pub destination_port_be: [u8; 2],
    pub reserved: [u8; 6],
    pub source: [u8; 16],
    pub destination: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketFlowEventFields {
    pub ip_family: u8,
    pub protocol: u8,
    pub tcp_state: u8,
    pub conntrack_status: u8,
    pub source_port_be: [u8; 2],
    pub destination_port_be: [u8; 2],
    pub source: [u8; 16],
    pub destination: [u8; 16],
}

impl PacketFlowEvent {
    pub const fn new(fields: PacketFlowEventFields) -> Self {
        Self {
            version: PACKET_FLOW_EVENT_VERSION,
            ip_family: fields.ip_family,
            protocol: fields.protocol,
            tcp_state: fields.tcp_state,
            conntrack_status: fields.conntrack_status,
            flags: 0,
            source_port_be: fields.source_port_be,
            destination_port_be: fields.destination_port_be,
            reserved: [0; 6],
            source: fields.source,
            destination: fields.destination,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PacketFlowEventError> {
        if bytes.len() != PACKET_FLOW_EVENT_LEN {
            return Err(PacketFlowEventError::InvalidLength {
                actual: bytes.len(),
                expected: PACKET_FLOW_EVENT_LEN,
            });
        }

        let mut source = [0_u8; 16];
        source.copy_from_slice(&bytes[16..32]);
        let mut destination = [0_u8; 16];
        destination.copy_from_slice(&bytes[32..48]);

        Ok(Self {
            version: bytes[0],
            ip_family: bytes[1],
            protocol: bytes[2],
            tcp_state: bytes[3],
            conntrack_status: bytes[4],
            flags: bytes[5],
            source_port_be: [bytes[6], bytes[7]],
            destination_port_be: [bytes[8], bytes[9]],
            reserved: [
                bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
            ],
            source,
            destination,
        })
    }

    pub fn write_bytes(&self, bytes: &mut [u8; PACKET_FLOW_EVENT_LEN]) {
        bytes[0] = self.version;
        bytes[1] = self.ip_family;
        bytes[2] = self.protocol;
        bytes[3] = self.tcp_state;
        bytes[4] = self.conntrack_status;
        bytes[5] = self.flags;
        bytes[6..8].copy_from_slice(&self.source_port_be);
        bytes[8..10].copy_from_slice(&self.destination_port_be);
        bytes[10..16].copy_from_slice(&self.reserved);
        bytes[16..32].copy_from_slice(&self.source);
        bytes[32..48].copy_from_slice(&self.destination);
    }

    pub const fn source_port(&self) -> u16 {
        u16::from_be_bytes(self.source_port_be)
    }

    pub const fn destination_port(&self) -> u16 {
        u16::from_be_bytes(self.destination_port_be)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketFlowEventError {
    InvalidLength { actual: usize, expected: usize },
}

impl fmt::Display for PacketFlowEventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { actual, expected } => {
                write!(
                    formatter,
                    "eBPF packet-flow event has {actual} bytes, expected {expected}"
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_flow_event_abi_is_fixed_width_and_round_trips() {
        assert_eq!(
            core::mem::size_of::<PacketFlowEvent>(),
            PACKET_FLOW_EVENT_LEN
        );
        assert_eq!(core::mem::align_of::<PacketFlowEvent>(), 8);

        let event = PacketFlowEvent::new(PacketFlowEventFields {
            ip_family: PACKET_FLOW_IP_FAMILY_IPV4,
            protocol: PACKET_FLOW_PROTOCOL_TCP,
            tcp_state: PACKET_FLOW_TCP_STATE_ESTABLISHED,
            conntrack_status: PACKET_FLOW_CONNTRACK_ASSURED,
            source_port_be: 443_u16.to_be_bytes(),
            destination_port_be: 6443_u16.to_be_bytes(),
            source: [192, 0, 2, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            destination: [100, 64, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        });
        let mut bytes = [0_u8; PACKET_FLOW_EVENT_LEN];
        event.write_bytes(&mut bytes);

        let Ok(parsed) = PacketFlowEvent::from_bytes(&bytes) else {
            panic!("event should parse");
        };
        assert_eq!(parsed, event);
    }
}
