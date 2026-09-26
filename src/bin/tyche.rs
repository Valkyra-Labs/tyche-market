//! `tyche`: cut symbols out of IEX HIST captures and check DEEP+ against
//! DEEP.
//!
//! ```text
//! tyche extract --symbols AAPL,SPY -o aapl_spy.tyc  <capture.pcap[.gz] | ->
//! tyche stats   <capture.pcap[.gz] | file.tyc>
//! tyche parity  <deep.tyc> <deep_plus.tyc> [--show N]
//! ```
//!
//! `-` reads standard input, so a day can be streamed from IEX without
//! storing it: `curl -s URL | tyche extract --symbols AAPL -o aapl.tyc -`.

use flate2::read::MultiGzDecoder;
use std::collections::{BTreeMap, HashSet};
use std::io::{BufReader, BufWriter, Read};
use std::path::Path;
use std::time::Instant;
use tyche_market::capture::{self, Capture};
use tyche_market::iextp::{udp_payload, Segment};
use tyche_market::pcap::PacketReader;
use tyche_market::{decode, parity, Symbol};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Open a file or stdin, un-gzipping when the stream starts with the gzip
/// magic.
fn open(path: &str) -> Result<Box<dyn Read>> {
    let raw: Box<dyn Read> = if path == "-" {
        Box::new(std::io::stdin().lock())
    } else {
        Box::new(std::fs::File::open(path)?)
    };
    let mut buffered = BufReader::with_capacity(1 << 20, raw);
    let head = std::io::BufRead::fill_buf(&mut buffered)?;
    if head.starts_with(&[0x1f, 0x8b]) {
        Ok(Box::new(BufReader::with_capacity(
            1 << 20,
            MultiGzDecoder::new(buffered),
        )))
    } else {
        Ok(Box::new(buffered))
    }
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

fn positional(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut skip = false;
    for a in args {
        if skip {
            skip = false;
            continue;
        }
        if a.starts_with("--") || a == "-o" {
            skip = true;
            continue;
        }
        out.push(a.clone());
    }
    out
}

fn extract(args: &[String]) -> Result<()> {
    let symbols: HashSet<Symbol> = arg_value(args, "--symbols")
        .map(|s| {
            s.split(',')
                .filter(|x| !x.is_empty())
                .map(Symbol::new)
                .collect()
        })
        .unwrap_or_default();
    let out_path = arg_value(args, "-o").ok_or("extract needs -o FILE")?;
    let input = positional(args)
        .into_iter()
        .next()
        .ok_or("extract needs an input")?;
    let t = Instant::now();
    let out = BufWriter::with_capacity(1 << 20, std::fs::File::create(&out_path)?);
    let stats = capture::extract(open(&input)?, &symbols, out)?;
    eprintln!(
        "protocol {:#06x}: {} packets, {} segments, {} messages, kept {}, duplicates {}, missing {}, other frames {} in {:.1} s -> {}",
        stats.protocol,
        stats.packets,
        stats.segments,
        stats.messages,
        stats.kept,
        stats.duplicates,
        stats.missing,
        stats.other_frames,
        t.elapsed().as_secs_f64(),
        out_path
    );
    Ok(())
}

fn stats(args: &[String]) -> Result<()> {
    let input = positional(args)
        .into_iter()
        .next()
        .ok_or("stats needs an input")?;
    let mut counts: BTreeMap<char, u64> = BTreeMap::new();
    let mut symbols: HashSet<Symbol> = HashSet::new();
    let (mut first, mut last) = (i64::MAX, i64::MIN);
    let mut count = |protocol: u16, msg: &[u8]| {
        let m = decode(protocol, msg);
        *counts
            .entry(*msg.first().unwrap_or(&0) as char)
            .or_insert(0) += 1;
        if let Some(s) = m.symbol() {
            symbols.insert(s);
        }
        if let Some(t) = m.time() {
            first = first.min(t);
            last = last.max(t);
        }
    };
    let protocol;
    if Path::new(&input).extension().is_some_and(|e| e == "tyc") {
        let bytes = std::fs::read(&input)?;
        let cap = Capture::parse(&bytes)?;
        protocol = cap.protocol;
        for msg in cap.messages() {
            count(protocol, msg?);
        }
    } else {
        let mut reader = PacketReader::new(open(&input)?)?;
        let mut p = 0;
        while let Some(packet) = reader.next_packet()? {
            let Some(seg) = udp_payload(packet.data).and_then(|u| Segment::parse(u).ok()) else {
                continue;
            };
            p = seg.protocol;
            for msg in seg.messages() {
                count(seg.protocol, msg?);
            }
        }
        protocol = p;
    }
    println!("protocol {protocol:#06x}");
    for (k, v) in &counts {
        println!("  {k:?}: {v}");
    }
    println!(
        "{} symbols; time {} .. {} (ns since epoch)",
        symbols.len(),
        first,
        last
    );
    Ok(())
}

fn load(path: &str) -> Result<(u16, Vec<tyche_market::Message>)> {
    let bytes = std::fs::read(path)?;
    let cap = Capture::parse(&bytes)?;
    let mut out = Vec::new();
    for msg in cap.messages() {
        out.push(decode(cap.protocol, msg?));
    }
    Ok((cap.protocol, out))
}

fn parity_cmd(args: &[String]) -> Result<()> {
    let files = positional(args);
    let [deep_path, plus_path] = files.as_slice() else {
        return Err("parity needs <deep.tyc> <deep_plus.tyc>".into());
    };
    let show: usize = arg_value(args, "--show")
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(5);
    let (dp, deep) = load(deep_path)?;
    let (pp, plus) = load(plus_path)?;
    if dp != tyche_market::iextp::PROTOCOL_DEEP || pp != tyche_market::iextp::PROTOCOL_DEEP_PLUS {
        return Err(format!(
            "expected DEEP (0x8004) then DEEP+ (0x8005), got {dp:#06x} and {pp:#06x}"
        )
        .into());
    }
    let t = Instant::now();
    let r = parity::check(deep, plus, show);
    let pct = |n: u64| 100.0 * n as f64 / r.checkpoints.max(1) as f64;
    println!(
        "checkpoints {}; full book equal {} ({:.4}%); top of book equal {} ({:.4}%)",
        r.checkpoints,
        r.full_book_equal,
        pct(r.full_book_equal),
        r.top_of_book_equal,
        pct(r.top_of_book_equal)
    );
    println!(
        "DEEP+ messages applied {}; time regressions {}; anomalies {:?}; {:.2} s",
        r.deep_plus_messages,
        r.deep_plus_time_regressions,
        r.anomalies,
        t.elapsed().as_secs_f64()
    );
    for m in &r.mismatches {
        println!("mismatch at {} {}:", m.time, m.symbol);
        for d in m.diffs.iter().take(8) {
            println!(
                "  {:?} {:.4}: DEEP {} DEEP+ {}",
                d.side,
                d.price as f64 / 10_000.0,
                d.deep,
                d.deep_plus
            );
        }
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest = args.get(1..).unwrap_or(&[]);
    let result = match args.first().map(String::as_str) {
        Some("extract") => extract(rest),
        Some("stats") => stats(rest),
        Some("parity") => parity_cmd(rest),
        _ => Err("usage: tyche extract --symbols A,B -o OUT.tyc INPUT | tyche stats INPUT | tyche parity DEEP.tyc DEEP_PLUS.tyc [--show N]".into()),
    };
    if let Err(e) = result {
        eprintln!("tyche: {e}");
        std::process::exit(1);
    }
}
