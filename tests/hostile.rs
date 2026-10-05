//! Damaged captures: the IEX sample captures cut short and corrupted at
//! random (from a fixed seed, so a failure repeats) must give an error or
//! fewer packets, never a panic and never a huge allocation.

use flate2::read::MultiGzDecoder;
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use tyche_market::capture;
use tyche_market::pcap::PacketReader;

/// The first `len` bytes of a sample capture, inflated.
fn prefix(name: &str, len: usize) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    MultiGzDecoder::new(File::open(path).expect("fixture"))
        .take(len as u64)
        .read_to_end(&mut out)
        .expect("inflate");
    out
}

/// xorshift64*: a small generator with no dependency, repeatable from its seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Values that sit on the edges of length and count fields.
const EDGES: [u32; 9] = [0, 1, 4, 11, 12, 16, 20, 0x7fff_ffff, 0xffff_fff0];

/// A few random changes to `bytes`: flipped bits, bytes set to 0 or 255,
/// a 32-bit field set to an edge value, a cut, a repeated slice.
fn mutate(rng: &mut Rng, bytes: &mut Vec<u8>) {
    for _ in 0..1 + rng.below(4) {
        if bytes.is_empty() {
            return;
        }
        let at = rng.below(bytes.len());
        match rng.below(6) {
            0 => bytes[at] ^= 1 << rng.below(8),
            1 => bytes[at] = 0,
            2 => bytes[at] = 0xff,
            3 if at + 4 <= bytes.len() => {
                let v = EDGES[rng.below(EDGES.len())];
                bytes[at..at + 4].copy_from_slice(&v.to_le_bytes());
            }
            4 => bytes.truncate(at),
            _ => {
                let end = (at + 1 + rng.below(64)).min(bytes.len());
                let slice = bytes[at..end].to_vec();
                bytes.splice(at..at, slice);
            }
        }
    }
}

/// Reads every packet, then extracts the IEX-TP messages as the command
/// line does; either may fail, neither may panic.
fn read(bytes: &[u8]) {
    if let Ok(mut reader) = PacketReader::new(bytes) {
        while let Ok(Some(_)) = reader.next_packet() {}
    }
    let _ = capture::extract(bytes, &HashSet::new(), std::io::sink());
}

#[test]
fn every_cut_of_the_samples_reads_or_fails_cleanly() {
    for name in [
        "dpls_sample_20241001.pcap.gz",
        "deep_sample_20180127.pcap.gz",
    ] {
        let bytes = prefix(name, 4096);
        for end in 0..bytes.len() {
            read(&bytes[..end]);
        }
    }
}

#[test]
fn corrupted_samples_read_or_fail_cleanly() {
    let seeds = [
        prefix("dpls_sample_20241001.pcap.gz", 16 * 1024),
        prefix("deep_sample_20180127.pcap.gz", 16 * 1024),
    ];
    let mut rng = Rng(0x7e5c_4e00_2026_1005);
    for round in 0..20_000 {
        let mut bytes = seeds[round % seeds.len()].clone();
        mutate(&mut rng, &mut bytes);
        let result = std::panic::catch_unwind(|| read(&bytes));
        assert!(result.is_ok(), "round {round} panicked");
    }
}
