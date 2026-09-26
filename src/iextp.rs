//! IEX Transport Protocol v1 (IEX-TP) segments inside UDP datagrams, and
//! the Ethernet/IPv4/UDP framing around them in HIST captures.
//!
//! Segment layout (IEX Transport Specification, all little endian):
//! version (1), reserved (1), message protocol id (2), channel id (4),
//! session id (4), payload length (2), message count (2), stream offset
//! (8), first message sequence number (8), send time (8); then `message
//! count` blocks of a 2-byte length and the message bytes.

use crate::Error;

/// Message protocol id of IEX DEEP (depth by price level).
pub const PROTOCOL_DEEP: u16 = 0x8004;
/// Message protocol id of IEX DEEP+ (depth by order).
pub const PROTOCOL_DEEP_PLUS: u16 = 0x8005;
/// Message protocol id of IEX TOPS.
pub const PROTOCOL_TOPS: u16 = 0x8003;

const HEADER_LEN: usize = 40;

/// The header of one IEX-TP segment and its payload.
#[derive(Debug, Clone, Copy)]
pub struct Segment<'a> {
    pub protocol: u16,
    pub channel: u32,
    pub session: u32,
    pub message_count: u16,
    pub first_sequence: u64,
    pub send_time_ns: i64,
    payload: &'a [u8],
}

fn le_u16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}

fn le_u64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("8 bytes"))
}

impl<'a> Segment<'a> {
    /// Parse one segment from a UDP payload.
    pub fn parse(udp: &'a [u8]) -> Result<Self, Error> {
        if udp.len() < HEADER_LEN {
            return Err(Error::Truncated("IEX-TP header"));
        }
        if udp[0] != 1 {
            return Err(Error::Format("IEX-TP version is not 1"));
        }
        let payload_len = le_u16(udp, 12) as usize;
        if udp.len() < HEADER_LEN + payload_len {
            return Err(Error::Truncated("IEX-TP payload"));
        }
        Ok(Self {
            protocol: le_u16(udp, 2),
            channel: le_u32(udp, 4),
            session: le_u32(udp, 8),
            message_count: le_u16(udp, 14),
            first_sequence: le_u64(udp, 24),
            send_time_ns: le_u64(udp, 32) as i64,
            payload: &udp[HEADER_LEN..HEADER_LEN + payload_len],
        })
    }

    /// The message blocks of this segment, in sequence order.
    pub fn messages(&self) -> Messages<'a> {
        Messages {
            rest: self.payload,
            left: self.message_count,
        }
    }
}

/// Iterator over the messages of a segment.
pub struct Messages<'a> {
    rest: &'a [u8],
    left: u16,
}

impl<'a> Iterator for Messages<'a> {
    type Item = Result<&'a [u8], Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        if self.rest.len() < 2 {
            self.left = 0;
            return Some(Err(Error::Truncated("IEX-TP message length")));
        }
        let len = le_u16(self.rest, 0) as usize;
        if self.rest.len() < 2 + len {
            self.left = 0;
            return Some(Err(Error::Truncated("IEX-TP message")));
        }
        let msg = &self.rest[2..2 + len];
        self.rest = &self.rest[2 + len..];
        Some(Ok(msg))
    }
}

/// The UDP payload of an Ethernet frame carrying IPv4/UDP (VLAN tags are
/// skipped), or `None` for anything else.
pub fn udp_payload(frame: &[u8]) -> Option<&[u8]> {
    let mut at = 12;
    let mut ether_type = u16::from_be_bytes([*frame.get(at)?, *frame.get(at + 1)?]);
    at += 2;
    while ether_type == 0x8100 || ether_type == 0x88a8 {
        ether_type = u16::from_be_bytes([*frame.get(at + 2)?, *frame.get(at + 3)?]);
        at += 4;
    }
    if ether_type != 0x0800 {
        return None;
    }
    let ip = frame.get(at..)?;
    let ihl = (*ip.first()? & 0x0f) as usize * 4;
    if ip.get(9) != Some(&17) || ihl < 20 {
        return None;
    }
    let total = u16::from_be_bytes([*ip.get(2)?, *ip.get(3)?]) as usize;
    let udp = ip.get(ihl..total.min(ip.len()))?;
    let udp_len = u16::from_be_bytes([*udp.get(4)?, *udp.get(5)?]) as usize;
    udp.get(8..udp_len.min(udp.len()))
}
