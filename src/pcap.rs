//! Packet capture reading: classic pcap (microsecond and nanosecond
//! variants, either byte order) and pcapng (section header, interface
//! description and enhanced/simple packet blocks). Only what is needed to
//! get link-layer frames and their capture times out of IEX HIST files.

use crate::Error;
use std::io::Read;

/// The longest record or block the reader accepts, in bytes. IEX frames
/// are under 2 KB; the cap keeps a damaged length field from asking for
/// gigabytes of memory before the read fails.
pub const MAX_RECORD: usize = 256 * 1024;

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
                if total > MAX_RECORD {
                    return Err(Error::Format("pcapng block longer than 256 KiB"));
                }
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
                if incl > MAX_RECORD {
                    return Err(Error::Format("pcap record longer than 256 KiB"));
                }
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
                if total > MAX_RECORD {
                    return Err(Error::Format("pcapng block longer than 256 KiB"));
                }
                if !read_exact_or_eof(&mut self.inner, &mut self.buf, total - 8)? {
                    return Err(Error::Truncated("pcapng block"));
                }
                let body = &self.buf[..total - 12];
                match block_type {
                    // Interface Description Block
                    0x0000_0001 => {
                        // Link type (2), reserved (2), snap length (4).
                        if body.len() < 8 {
                            return Err(Error::Truncated("pcapng interface description"));
                        }
                        self.link_types.push(u16_at(body, 0, big_endian));
                        self.ts_units.push(ng_ts_units(body, big_endian)?);
                    }
                    // Enhanced Packet Block
                    0x0000_0006 => {
                        // Interface (4), timestamp (8), captured and
                        // original length (4 each), then the packet.
                        if body.len() < 20 {
                            return Err(Error::Truncated("pcapng enhanced packet block"));
                        }
                        let iface = u32_at(body, 0, big_endian) as usize;
                        let hi = u32_at(body, 4, big_endian) as u64;
                        let lo = u32_at(body, 8, big_endian) as u64;
                        let caplen = u32_at(body, 12, big_endian) as usize;
                        let units = self.ts_units.get(iface).copied().unwrap_or(1_000_000);
                        let raw = (hi << 32) | lo;
                        let time_ns = if units >= 1_000_000_000 {
                            raw / (units / 1_000_000_000)
                        } else {
                            raw.checked_mul(1_000_000_000 / units)
                                .ok_or(Error::Format("pcapng timestamp out of range"))?
                        };
                        if caplen > body.len() - 20 {
                            return Err(Error::Format("pcapng packet longer than its block"));
                        }
                        let data = &self.buf[20..20 + caplen];
                        return Ok(Some(Packet { time_ns, data }));
                    }
                    // Simple Packet Block
                    0x0000_0003 => {
                        // Original length (4), then the packet.
                        if body.len() < 4 {
                            return Err(Error::Truncated("pcapng simple packet block"));
                        }
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
/// A resolution finer than a u64 can count (10^20 and up, 2^64 and up) is
/// an error.
fn ng_ts_units(body: &[u8], be: bool) -> Result<u64, Error> {
    let mut at = 8; // link type (2), reserved (2), snaplen (4)
    while at + 4 <= body.len() {
        let code = u16_at(body, at, be);
        let len = u16_at(body, at + 2, be) as usize;
        if code == 0 {
            break;
        }
        if code == 9 && len >= 1 && at + 4 < body.len() {
            let v = body[at + 4];
            let units = if v & 0x80 == 0 {
                10u64.checked_pow(v as u32)
            } else {
                1u64.checked_shl((v & 0x7f) as u32)
            };
            return units.ok_or(Error::Format("pcapng timestamp resolution"));
        }
        at += 4 + len.div_ceil(4) * 4;
    }
    Ok(1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every packet of `bytes`, or the first error. A panic fails the test.
    fn read_all(bytes: &[u8]) -> Result<Vec<(u64, Vec<u8>)>, Error> {
        let mut reader = PacketReader::new(bytes)?;
        let mut out = Vec::new();
        while let Some(p) = reader.next_packet()? {
            out.push((p.time_ns, p.data.to_vec()));
        }
        Ok(out)
    }

    fn le32(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    /// A classic little-endian microsecond pcap with two Ethernet frames.
    fn classic() -> Vec<u8> {
        let mut b = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
        b.extend([0; 8]);
        b.extend(le32(65_535));
        b.extend(le32(1));
        for (sec, usec, data) in [(10u32, 5u32, &b"frame one"[..]), (11, 6, &b"two"[..])] {
            b.extend(le32(sec));
            b.extend(le32(usec));
            b.extend(le32(data.len() as u32));
            b.extend(le32(data.len() as u32));
            b.extend(data);
        }
        b
    }

    /// A pcapng section header block, little endian, with no options.
    fn shb() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend(le32(0x0a0d_0d0a));
        b.extend(le32(28));
        b.extend(le32(0x1a2b_3c4d));
        b.extend([1, 0, 0, 0]);
        b.extend([0xff; 8]);
        b.extend(le32(28));
        b
    }

    /// A pcapng block of `kind` around `body` (padded to four bytes).
    fn block(kind: u32, body: &[u8]) -> Vec<u8> {
        let padded = body.len().div_ceil(4) * 4;
        let total = (12 + padded) as u32;
        let mut b = Vec::new();
        b.extend(le32(kind));
        b.extend(le32(total));
        b.extend(body);
        b.resize(8 + padded, 0);
        b.extend(le32(total));
        b
    }

    /// An interface description: Ethernet, with `options` after the
    /// fixed part (end-of-options added).
    fn idb(options: &[u8]) -> Vec<u8> {
        let mut body = vec![1, 0, 0, 0];
        body.extend(le32(65_535));
        body.extend(options);
        if !options.is_empty() {
            body.extend([0; 4]);
        }
        block(1, &body)
    }

    fn epb(iface: u32, time: u64, data: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend(le32(iface));
        body.extend(le32((time >> 32) as u32));
        body.extend(le32(time as u32));
        body.extend(le32(data.len() as u32));
        body.extend(le32(data.len() as u32));
        body.extend(data);
        block(6, &body)
    }

    /// A pcapng capture: one interface in nanoseconds, two packets.
    fn ng() -> Vec<u8> {
        let mut b = shb();
        b.extend(idb(&[9, 0, 1, 0, 9, 0, 0, 0]));
        b.extend(epb(0, 1_000, b"frame one"));
        b.extend(epb(0, 2_000, b"two"));
        b
    }

    #[test]
    fn well_formed_captures_read_in_full() {
        let c = read_all(&classic()).expect("classic");
        assert_eq!(c.len(), 2);
        assert_eq!(c[0], (10_000_005_000, b"frame one".to_vec()));
        let n = read_all(&ng()).expect("pcapng");
        assert_eq!(
            n,
            vec![(1_000, b"frame one".to_vec()), (2_000, b"two".to_vec())]
        );
    }

    fn assert_err(bytes: &[u8], what: &str) {
        assert!(read_all(bytes).is_err(), "{what}: accepted");
    }

    #[test]
    fn an_interface_description_too_short_for_its_fields_is_an_error() {
        let mut b = shb();
        b.extend([1, 0, 0, 0, 12, 0, 0, 0, 12, 0, 0, 0]);
        assert_err(&b, "empty IDB");
    }

    #[test]
    fn an_enhanced_packet_block_too_short_for_its_fields_is_an_error() {
        let mut b = shb();
        b.extend(idb(&[]));
        b.extend([6, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0]);
        assert_err(&b, "EPB with a 4-byte body");
    }

    #[test]
    fn a_packet_longer_than_its_block_is_an_error() {
        let mut b = shb();
        b.extend(idb(&[]));
        let mut packet = epb(0, 1, b"data");
        packet[20..24].copy_from_slice(&le32(4096));
        b.extend(packet);
        assert_err(&b, "captured length past the block");
    }

    #[test]
    fn a_simple_packet_block_with_no_body_is_an_error() {
        let mut b = shb();
        b.extend([3, 0, 0, 0, 12, 0, 0, 0, 12, 0, 0, 0]);
        assert_err(&b, "empty SPB");
    }

    #[test]
    fn a_timestamp_resolution_past_what_u64_holds_is_an_error() {
        for resolution in [64u8, 20, 0x80 | 64] {
            let mut b = shb();
            b.extend(idb(&[9, 0, 1, 0, resolution, 0, 0, 0]));
            b.extend(epb(0, 1, b"data"));
            assert_err(&b, &format!("if_tsresol {resolution:#x}"));
        }
    }

    #[test]
    fn a_timestamp_that_overflows_in_nanoseconds_is_an_error() {
        let mut b = shb();
        // Seconds: every raw unit is 10^9 ns.
        b.extend(idb(&[9, 0, 1, 0, 0, 0, 0, 0]));
        b.extend(epb(0, u64::MAX / 2, b"data"));
        assert_err(&b, "timestamp overflow");
    }

    #[test]
    fn a_record_length_of_gigabytes_is_refused_before_reading() {
        let mut b = classic()[..24].to_vec();
        b.extend(le32(1));
        b.extend(le32(0));
        b.extend(le32(0xffff_fff0));
        b.extend(le32(0xffff_fff0));
        let mut reader = PacketReader::new(&b[..]).expect("header");
        assert!(reader.next_packet().is_err());
        assert!(
            reader.buf.capacity() <= MAX_RECORD,
            "buffer grew to {}",
            reader.buf.capacity()
        );
    }

    #[test]
    fn a_block_length_of_gigabytes_is_refused_before_reading() {
        let mut header = shb();
        header[4..8].copy_from_slice(&le32(0xffff_fff0));
        assert_err(&header, "section header of 4 GiB");
        let mut b = shb();
        b.extend([6, 0, 0, 0]);
        b.extend(le32(0xffff_fff0));
        let mut reader = PacketReader::new(&b[..]).expect("header");
        assert!(reader.next_packet().is_err());
        assert!(
            reader.buf.capacity() <= MAX_RECORD,
            "buffer grew to {}",
            reader.buf.capacity()
        );
    }

    #[test]
    fn every_truncation_is_an_error_or_a_shorter_capture() {
        for full in [classic(), ng()] {
            let whole = read_all(&full).expect("whole").len();
            for end in 0..full.len() {
                if let Ok(packets) = read_all(&full[..end]) {
                    assert!(packets.len() < whole, "cut at {end} read every packet");
                }
            }
        }
    }
}
