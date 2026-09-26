//! Packet capture reading: classic pcap (microsecond and nanosecond
//! variants, either byte order) and pcapng (section header, interface
//! description and enhanced/simple packet blocks). Only what is needed to
//! get link-layer frames and their capture times out of IEX HIST files.

use crate::Error;
use std::io::Read;

/// One captured frame: capture time in nanoseconds since the Unix epoch
/// (0 when the format does not carry one) and the link-layer bytes.
pub struct Packet<'a> {
    pub time_ns: u64,
    pub data: &'a [u8],
}

enum Format {
    Classic { big_endian: bool, nanos: bool },
    Ng { big_endian: bool },
}

/// Streaming reader over any `Read` (a file, a gzip decoder, stdin).
pub struct PacketReader<R: Read> {
    inner: R,
    format: Format,
    buf: Vec<u8>,
    /// Link type of the capture (1 = Ethernet); pcapng keeps one per interface.
    link_types: Vec<u16>,
    /// Timestamp resolution per pcapng interface, in units per second.
    ts_units: Vec<u64>,
}

fn u16_at(b: &[u8], at: usize, be: bool) -> u16 {
    let v = [b[at], b[at + 1]];
    if be {
        u16::from_be_bytes(v)
    } else {
        u16::from_le_bytes(v)
    }
}

fn u32_at(b: &[u8], at: usize, be: bool) -> u32 {
    let v = [b[at], b[at + 1], b[at + 2], b[at + 3]];
    if be {
        u32::from_be_bytes(v)
    } else {
        u32::from_le_bytes(v)
    }
}

/// Read exactly `n` bytes into `buf`; `Ok(false)` on a clean end of stream
/// before the first byte.
fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut Vec<u8>, n: usize) -> Result<bool, Error> {
    buf.resize(n, 0);
    let mut filled = 0;
    while filled < n {
        match r.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => return Err(Error::Truncated("capture ends inside a record")),
            Ok(k) => filled += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(true)
}

impl<R: Read> PacketReader<R> {
    pub fn new(mut inner: R) -> Result<Self, Error> {
        let mut head = Vec::new();
        if !read_exact_or_eof(&mut inner, &mut head, 4)? {
            return Err(Error::Format("empty capture"));
        }
        let magic = [head[0], head[1], head[2], head[3]];
        let mut reader = match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] => Self::classic(inner, false, false),
            [0xa1, 0xb2, 0xc3, 0xd4] => Self::classic(inner, true, false),
            [0x4d, 0x3c, 0xb2, 0xa1] => Self::classic(inner, false, true),
            [0xa1, 0xb2, 0x3c, 0x4d] => Self::classic(inner, true, true),
            [0x0a, 0x0d, 0x0d, 0x0a] => Self {
                inner,
                format: Format::Ng { big_endian: false },
                buf: Vec::new(),
                link_types: Vec::new(),
                ts_units: Vec::new(),
            },
            _ => return Err(Error::Format("not a pcap or pcapng capture")),
        };
        match reader.format {
            Format::Classic { big_endian, .. } => {
                let mut rest = Vec::new();
                if !read_exact_or_eof(&mut reader.inner, &mut rest, 20)? {
                    return Err(Error::Truncated("pcap global header"));
                }
                let link = u32_at(&rest, 16, big_endian) as u16;
                reader.link_types.push(link);
            }
            Format::Ng { .. } => {
                // The section header's block type was the magic; read the
                // rest of it here to learn the byte order.
                let mut len_and_bom = Vec::new();
                if !read_exact_or_eof(&mut reader.inner, &mut len_and_bom, 8)? {
                    return Err(Error::Truncated("pcapng section header"));
                }
                let be = match [
                    len_and_bom[4],
                    len_and_bom[5],
                    len_and_bom[6],
                    len_and_bom[7],
                ] {
                    [0x4d, 0x3c, 0x2b, 0x1a] => false,
                    [0x1a, 0x2b, 0x3c, 0x4d] => true,
                    _ => return Err(Error::Format("pcapng byte-order magic")),
                };
                reader.format = Format::Ng { big_endian: be };
                let total = u32_at(&len_and_bom, 0, be) as usize;
                let mut skip = Vec::new();
                if total < 12 || !read_exact_or_eof(&mut reader.inner, &mut skip, total - 12)? {
                    return Err(Error::Truncated("pcapng section header"));
                }
            }
        }
        Ok(reader)
    }

    fn classic(inner: R, big_endian: bool, nanos: bool) -> Self {
        Self {
            inner,
            format: Format::Classic { big_endian, nanos },
            buf: Vec::new(),
            link_types: Vec::new(),
            ts_units: Vec::new(),
        }
    }

    /// Link type of the first interface (1 = Ethernet).
    pub fn link_type(&self) -> Option<u16> {
        self.link_types.first().copied()
    }

    /// The next frame, or `None` at the end of the capture.
    pub fn next_packet(&mut self) -> Result<Option<Packet<'_>>, Error> {
        match self.format {
            Format::Classic { big_endian, nanos } => {
                let mut head = [0u8; 16];
                let mut h = Vec::new();
                if !read_exact_or_eof(&mut self.inner, &mut h, 16)? {
                    return Ok(None);
                }
                head.copy_from_slice(&h);
                let sec = u32_at(&head, 0, big_endian) as u64;
                let frac = u32_at(&head, 4, big_endian) as u64;
                let incl = u32_at(&head, 8, big_endian) as usize;
                if !read_exact_or_eof(&mut self.inner, &mut self.buf, incl)? && incl > 0 {
                    return Err(Error::Truncated("pcap packet data"));
                }
                let time_ns = sec * 1_000_000_000 + if nanos { frac } else { frac * 1000 };
                Ok(Some(Packet {
                    time_ns,
                    data: &self.buf[..incl],
                }))
            }
            Format::Ng { big_endian } => loop {
                let mut h = Vec::new();
                if !read_exact_or_eof(&mut self.inner, &mut h, 8)? {
                    return Ok(None);
                }
                let block_type = u32_at(&h, 0, big_endian);
                let total = u32_at(&h, 4, big_endian) as usize;
                if total < 12 {
                    return Err(Error::Format("pcapng block length"));
                }
                if !read_exact_or_eof(&mut self.inner, &mut self.buf, total - 8)? {
                    return Err(Error::Truncated("pcapng block"));
                }
                let body = &self.buf[..total - 12];
                match block_type {
                    // Interface Description Block
                    0x0000_0001 => {
                        self.link_types.push(u16_at(body, 0, big_endian));
                        self.ts_units.push(ng_ts_units(body, big_endian));
                    }
                    // Enhanced Packet Block
                    0x0000_0006 => {
                        let iface = u32_at(body, 0, big_endian) as usize;
                        let hi = u32_at(body, 4, big_endian) as u64;
                        let lo = u32_at(body, 8, big_endian) as u64;
                        let caplen = u32_at(body, 12, big_endian) as usize;
                        let units = self.ts_units.get(iface).copied().unwrap_or(1_000_000);
                        let raw = (hi << 32) | lo;
                        let time_ns = if units >= 1_000_000_000 {
                            raw / (units / 1_000_000_000)
                        } else {
                            raw * (1_000_000_000 / units)
                        };
                        let start = 20;
                        let data = &self.buf[start..start + caplen];
                        return Ok(Some(Packet { time_ns, data }));
                    }
                    // Simple Packet Block
                    0x0000_0003 => {
                        let data = &self.buf[4..total - 12];
                        return Ok(Some(Packet { time_ns: 0, data }));
                    }
                    // Section headers, statistics, name resolution: skipped.
                    _ => {}
                }
            },
        }
    }
}

/// Timestamp units per second from the if_tsresol option (default 10^6).
fn ng_ts_units(body: &[u8], be: bool) -> u64 {
    let mut at = 8; // link type (2), reserved (2), snaplen (4)
    while at + 4 <= body.len() {
        let code = u16_at(body, at, be);
        let len = u16_at(body, at + 2, be) as usize;
        if code == 0 {
            break;
        }
        if code == 9 && len >= 1 && at + 4 < body.len() {
            let v = body[at + 4];
            return if v & 0x80 == 0 {
                10u64.pow(v as u32)
            } else {
                1u64 << (v & 0x7f)
            };
        }
        at += 4 + len.div_ceil(4) * 4;
    }
    1_000_000
}
