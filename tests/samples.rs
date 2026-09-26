//! Decoding of the IEX sample captures, extraction round trips, and the
//! parity check on synthetic streams.

use flate2::read::MultiGzDecoder;
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use tyche_market::capture::{self, Capture};
use tyche_market::iextp::{udp_payload, Segment, PROTOCOL_DEEP, PROTOCOL_DEEP_PLUS};
use tyche_market::pcap::PacketReader;
use tyche_market::{decode, parity, Message, Side, Symbol};

fn fixture(name: &str) -> MultiGzDecoder<File> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    MultiGzDecoder::new(File::open(path).expect("fixture"))
}

fn type_counts(name: &str) -> (u16, BTreeMap<u8, u64>) {
    let mut reader = PacketReader::new(fixture(name)).expect("capture");
    let mut counts = BTreeMap::new();
    let mut protocol = 0;
    while let Some(p) = reader.next_packet().expect("packet") {
        let seg = Segment::parse(udp_payload(p.data).expect("udp")).expect("segment");
        protocol = seg.protocol;
        for m in seg.messages() {
            *counts.entry(m.expect("message")[0]).or_insert(0) += 1;
        }
    }
    (protocol, counts)
}

#[test]
fn deep_plus_sample_decodes_order_messages_from_classic_pcap() {
    let (protocol, c) = type_counts("dpls_sample_20241001.pcap.gz");
    assert_eq!(protocol, PROTOCOL_DEEP_PLUS);
    assert_eq!(c[&b'a'], 216);
    assert_eq!(c[&b'R'], 171);
    assert_eq!(c[&b'L'], 41);
    assert_eq!(c[&b'M'], 3);
}

#[test]
fn deep_sample_decodes_price_levels_from_pcapng() {
    let (protocol, c) = type_counts("deep_sample_20180127.pcap.gz");
    assert_eq!(protocol, PROTOCOL_DEEP);
    assert_eq!(c[&b'8'], 12124);
    assert_eq!(c[&b'5'], 18005);
}

#[test]
fn extraction_keeps_only_the_selected_symbols_and_round_trips() {
    // Everything first, to find a symbol with order activity.
    let mut all = Vec::new();
    let stats = capture::extract(
        fixture("dpls_sample_20241001.pcap.gz"),
        &HashSet::new(),
        &mut all,
    )
    .expect("extract");
    assert_eq!(stats.kept, stats.messages - stats.duplicates);
    let cap = Capture::parse(&all).expect("capture");
    let busiest = {
        let mut n: BTreeMap<Symbol, u64> = BTreeMap::new();
        for m in cap.messages() {
            if let Message::AddOrder { symbol, .. } = decode(cap.protocol, m.expect("record")) {
                *n.entry(symbol).or_insert(0) += 1;
            }
        }
        n.into_iter().max_by_key(|(_, c)| *c).expect("some adds").0
    };

    let mut one = Vec::new();
    let want: HashSet<Symbol> = [busiest].into_iter().collect();
    capture::extract(fixture("dpls_sample_20241001.pcap.gz"), &want, &mut one).expect("extract");
    let cap = Capture::parse(&one).expect("capture");
    assert_eq!(cap.protocol, PROTOCOL_DEEP_PLUS);
    let mut adds = 0;
    for m in cap.messages() {
        let m = decode(cap.protocol, m.expect("record"));
        if let Some(s) = m.symbol() {
            assert_eq!(s, busiest);
        }
        if matches!(m, Message::AddOrder { .. }) {
            adds += 1;
        }
    }
    assert!(adds > 0);
}

fn level(side: Side, complete: bool, time: i64, size: u32, price: i64) -> Message {
    Message::PriceLevel {
        side,
        complete,
        time,
        symbol: Symbol::new("ZIEXT"),
        size,
        price,
    }
}

fn add(time: i64, id: i64, side: Side, size: u32, price: i64) -> Message {
    Message::AddOrder {
        side,
        time,
        symbol: Symbol::new("ZIEXT"),
        order_id: id,
        size,
        price,
    }
}

#[test]
fn parity_is_exact_on_matching_streams_and_reports_a_divergence() {
    let deep = vec![
        level(Side::Buy, true, 10, 100, 990_500),
        level(Side::Sell, false, 20, 50, 991_000),
        level(Side::Buy, true, 20, 300, 990_500),
    ];
    let plus = vec![
        add(10, 1, Side::Buy, 100, 990_500),
        add(20, 2, Side::Buy, 200, 990_500),
        add(20, 3, Side::Sell, 50, 991_000),
    ];
    let r = parity::check(deep.clone(), plus, 3);
    assert_eq!(r.checkpoints, 2);
    assert_eq!(r.full_book_equal, 2);

    // A missing order on the DEEP+ side is found and located.
    let plus = vec![
        add(10, 1, Side::Buy, 100, 990_500),
        add(20, 3, Side::Sell, 50, 991_000),
    ];
    let r = parity::check(deep, plus, 3);
    assert_eq!(r.full_book_equal, 1);
    assert_eq!(r.mismatches.len(), 1);
    assert_eq!(r.mismatches[0].time, 20);
    assert_eq!(r.mismatches[0].diffs[0].deep, 300);
    assert_eq!(r.mismatches[0].diffs[0].deep_plus, 100);
}
