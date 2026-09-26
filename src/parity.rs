//! Parity between DEEP+ (order by order) and DEEP (by price level) for the
//! same day: the DEEP+ book, aggregated by price, must equal the DEEP book
//! at every point where DEEP marks an event as complete.
//!
//! The streams are aligned by timestamp. Messages with the same timestamp
//! were caused by the same event in the IEX trading system (DEEP+
//! Specification, "Timestamp Relationships"), so at a DEEP checkpoint with
//! time T every DEEP+ message with time <= T has happened and none after.

use crate::book::{Anomalies, LevelBook, Levels, OrderBook};
use crate::message::{Message, Price, Side, Symbol};
use std::collections::HashMap;

/// One price where the two books disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LevelDiff {
    pub side: Side,
    pub price: Price,
    pub deep: u64,
    pub deep_plus: u64,
}

/// A checkpoint where the books disagree.
#[derive(Debug, Clone)]
pub struct Mismatch {
    pub time: i64,
    pub symbol: Symbol,
    pub diffs: Vec<LevelDiff>,
}

/// Parity result for a pair of streams.
#[derive(Debug, Default, Clone)]
pub struct Report {
    /// DEEP event-complete points compared.
    pub checkpoints: u64,
    /// Checkpoints where every level on both sides was equal.
    pub full_book_equal: u64,
    /// Checkpoints where the best bid and best ask (price and size) were
    /// equal.
    pub top_of_book_equal: u64,
    /// The first mismatches, in time order (at most `keep_mismatches`).
    pub mismatches: Vec<Mismatch>,
    /// DEEP+ messages applied.
    pub deep_plus_messages: u64,
    /// DEEP+ messages whose timestamp was lower than an earlier one of the
    /// same symbol (the alignment assumes this does not happen).
    pub deep_plus_time_regressions: u64,
    /// Book anomalies summed over symbols.
    pub anomalies: Anomalies,
}

fn diff(deep: &Levels, plus: &Levels) -> Vec<LevelDiff> {
    let mut out = Vec::new();
    for (side, a, b) in [
        (Side::Buy, &deep.bids, &plus.bids),
        (Side::Sell, &deep.asks, &plus.asks),
    ] {
        let mut prices: Vec<Price> = a.keys().chain(b.keys()).copied().collect();
        prices.sort_unstable();
        prices.dedup();
        for price in prices {
            let (x, y) = (
                a.get(&price).copied().unwrap_or(0),
                b.get(&price).copied().unwrap_or(0),
            );
            if x != y {
                out.push(LevelDiff {
                    side,
                    price,
                    deep: x,
                    deep_plus: y,
                });
            }
        }
    }
    out
}

/// Run the parity check. Both iterators yield decoded messages in feed
/// order; symbols not present in both are compared as found.
pub fn check<D, P>(deep: D, deep_plus: P, keep_mismatches: usize) -> Report
where
    D: IntoIterator<Item = Message>,
    P: IntoIterator<Item = Message>,
{
    let mut report = Report::default();
    let mut level_books: HashMap<Symbol, LevelBook> = HashMap::new();
    let mut order_books: HashMap<Symbol, OrderBook> = HashMap::new();
    let mut last_time: HashMap<Symbol, i64> = HashMap::new();
    let mut plus = deep_plus.into_iter().peekable();

    for m in deep {
        let Some(symbol) = m.symbol() else { continue };
        let complete = level_books.entry(symbol).or_default().apply(&m);
        if !complete {
            continue;
        }
        let t = m.time().unwrap_or(i64::MIN);
        while let Some(p) = plus.peek() {
            if p.time().is_some_and(|pt| pt > t) {
                break;
            }
            let p = plus.next().expect("peeked");
            if let (Some(s), Some(pt)) = (p.symbol(), p.time()) {
                let last = last_time.entry(s).or_insert(pt);
                if pt < *last {
                    report.deep_plus_time_regressions += 1;
                }
                *last = pt.max(*last);
                order_books.entry(s).or_default().apply(&p);
                report.deep_plus_messages += 1;
            }
        }
        report.checkpoints += 1;
        let deep_levels = level_books[&symbol].levels();
        let empty = OrderBook::default();
        let plus_levels = order_books.get(&symbol).unwrap_or(&empty).levels();
        if deep_levels == plus_levels {
            report.full_book_equal += 1;
            report.top_of_book_equal += 1;
            continue;
        }
        if deep_levels.best() == plus_levels.best() {
            report.top_of_book_equal += 1;
        }
        if report.mismatches.len() < keep_mismatches {
            report.mismatches.push(Mismatch {
                time: t,
                symbol,
                diffs: diff(deep_levels, plus_levels),
            });
        }
    }
    for b in order_books.values() {
        report.anomalies.unknown_order += b.anomalies.unknown_order;
        report.anomalies.duplicate_order += b.anomalies.duplicate_order;
        report.anomalies.overfill += b.anomalies.overfill;
    }
    report
}
