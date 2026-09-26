//! Symbol-filtered captures: the messages of a few symbols cut out of a
//! day of IEX HIST data, in feed order, small enough to ship with a demo.
//!
//! File layout (all little endian):
//! magic `TYCHECAP` (8 bytes), format version (u16, 1), IEX-TP message
//! protocol id (u16), reserved (u32); then one record per message: length
//! (u16) and the message bytes exactly as sent by IEX.
//!
//! Extraction reads the IEX-TP sequence numbers: segments already seen
//! (the same data received twice) are skipped, and missing ranges are
//! counted, so a capture states how complete it is.

use crate::iextp::{udp_payload, Segment};
use crate::message::{raw_symbol, Symbol};
use crate::pcap::PacketReader;
use crate::Error;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};

pub const MAGIC: &[u8; 8] = b"TYCHECAP";
pub const VERSION: u16 = 1;

/// What an extraction saw.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ExtractStats {
    pub protocol: u16,
    pub packets: u64,
    pub segments: u64,
    pub messages: u64,
    /// Messages written (the selected symbols plus system events).
    pub kept: u64,
    /// Messages skipped because their sequence number was already seen.
    pub duplicates: u64,
    /// Sequence numbers never received.
    pub missing: u64,
    /// Frames that were not IEX-TP (other traffic, damaged segments).
    pub other_frames: u64,
}

/// Cut the selected symbols (and all symbol-less messages, such as system
/// events) out of a pcap or pcapng capture of one IEX-TP feed. An empty
/// `symbols` set keeps everything.
pub fn extract<R: Read, W: Write>(
    input: R,
    symbols: &HashSet<Symbol>,
    mut out: W,
) -> Result<ExtractStats, Error> {
    let mut reader = PacketReader::new(input)?;
    let mut stats = ExtractStats::default();
    // Next expected sequence number per (channel, session).
    let mut expected: HashMap<(u32, u32), u64> = HashMap::new();
    let mut header_written = false;
    while let Some(packet) = reader.next_packet()? {
        stats.packets += 1;
        let Some(udp) = udp_payload(packet.data) else {
            stats.other_frames += 1;
            continue;
        };
        let Ok(segment) = Segment::parse(udp) else {
            stats.other_frames += 1;
            continue;
        };
        if !header_written {
            stats.protocol = segment.protocol;
            write_header(&mut out, segment.protocol)?;
            header_written = true;
        } else if segment.protocol != stats.protocol {
            return Err(Error::Format("capture mixes IEX-TP protocols"));
        }
        stats.segments += 1;
        let key = (segment.channel, segment.session);
        let next = expected.entry(key).or_insert(segment.first_sequence);
        if segment.first_sequence > *next {
            stats.missing += segment.first_sequence - *next;
            *next = segment.first_sequence;
        }
        let already = next.saturating_sub(segment.first_sequence);
        for (i, msg) in segment.messages().enumerate() {
            let msg = msg?;
            stats.messages += 1;
            if (i as u64) < already {
                stats.duplicates += 1;
                continue;
            }
            *next += 1;
            let keep = symbols.is_empty()
                || match raw_symbol(msg) {
                    None => true,
                    Some(s) => symbols.contains(&Symbol(s)),
                };
            if keep {
                write_record(&mut out, msg)?;
                stats.kept += 1;
            }
        }
    }
    if !header_written {
        return Err(Error::Format("no IEX-TP segments in the capture"));
    }
    out.flush()?;
    Ok(stats)
}

/// Keep only the selected symbols (and symbol-less messages) of an
/// existing capture. Returns the number of messages written.
pub fn filter<W: Write>(
    capture: &[u8],
    symbols: &HashSet<Symbol>,
    mut out: W,
) -> Result<u64, Error> {
    let cap = Capture::parse(capture)?;
    write_header(&mut out, cap.protocol)?;
    let mut kept = 0;
    for msg in cap.messages() {
        let msg = msg?;
        let keep = symbols.is_empty()
            || match raw_symbol(msg) {
                None => true,
                Some(s) => symbols.contains(&Symbol(s)),
            };
        if keep {
            write_record(&mut out, msg)?;
            kept += 1;
        }
    }
    out.flush()?;
    Ok(kept)
}

fn write_header<W: Write>(out: &mut W, protocol: u16) -> Result<(), Error> {
    out.write_all(MAGIC)?;
    out.write_all(&VERSION.to_le_bytes())?;
    out.write_all(&protocol.to_le_bytes())?;
    out.write_all(&[0; 4])?;
    Ok(())
}

fn write_record<W: Write>(out: &mut W, msg: &[u8]) -> Result<(), Error> {
    let len =
        u16::try_from(msg.len()).map_err(|_| Error::Format("message longer than 65535 bytes"))?;
    out.write_all(&len.to_le_bytes())?;
    out.write_all(msg)?;
    Ok(())
}

/// A capture held in memory (as the web app loads it).
pub struct Capture<'a> {
    pub protocol: u16,
    records: &'a [u8],
}

impl<'a> Capture<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < 16 || &bytes[..8] != MAGIC {
            return Err(Error::Format("not a tyche capture"));
        }
        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if version != VERSION {
            return Err(Error::Format("unsupported capture version"));
        }
        Ok(Self {
            protocol: u16::from_le_bytes([bytes[10], bytes[11]]),
            records: &bytes[16..],
        })
    }

    /// Raw messages in feed order.
    pub fn messages(&self) -> Records<'a> {
        Records { rest: self.records }
    }
}

/// Iterator over the raw messages of a capture.
pub struct Records<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Records<'a> {
    type Item = Result<&'a [u8], Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        if self.rest.len() < 2 {
            self.rest = &[];
            return Some(Err(Error::Truncated("capture record length")));
        }
        let len = u16::from_le_bytes([self.rest[0], self.rest[1]]) as usize;
        if self.rest.len() < 2 + len {
            self.rest = &[];
            return Some(Err(Error::Truncated("capture record")));
        }
        let msg = &self.rest[2..2 + len];
        self.rest = &self.rest[2 + len..];
        Some(Ok(msg))
    }
}
