//! Parity between DEEP+ (order by order) and DEEP (by price level) for the
//! same day: the DEEP+ book, aggregated by price, must equal the DEEP book
//! at every point where DEEP marks an event as complete.
//!
//! The streams are aligned by timestamp, symbol by symbol. Messages with
//! the same timestamp were caused by the same event in the IEX trading
//! system, so at a DEEP checkpoint with time T every DEEP+ message of that
//! symbol with time <= T has happened and none after. Timestamps are only
//! ordered within a symbol ("No progression of Timestamps between messages
//! having different Symbols may be expected", DEEP+ Specification), so
//! each symbol keeps its own queue: advancing one shared stream until a
//! later timestamp stalls on another symbol's message and leaves this
//! symbol's earlier messages unapplied (the first version of this check
//! did that, and reported 0.93% of checkpoints as disagreeing).

use crate::book::{Anomalies, LevelBook, Levels, OrderBook};
use crate::message::{Message, Price, Side, Symbol};
use std::collections::{HashMap, VecDeque};

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
    /// Runs of consecutive disagreeing checkpoints of one symbol, ended
    /// by an agreeing one (or by the end of the data).
    pub episodes: Vec<Episode>,
    /// Checkpoints and disagreements per symbol.
    pub per_symbol: Vec<(Symbol, u64, u64)>,
}

/// A run of disagreement for one symbol.
#[derive(Debug, Clone)]
pub struct Episode {
    pub symbol: Symbol,
    /// Time of the first disagreeing checkpoint.
    pub start: i64,
    /// Time of the checkpoint that agreed again (`None`: never did).
    pub end: Option<i64>,
    /// Disagreeing checkpoints in the run.
    pub checkpoints: u64,
    /// Every differing level in the run was smaller than 100 shares.
    pub odd_lot_only: bool,
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
    // DEEP+ messages per symbol, in feed order.
    let mut queues: HashMap<Symbol, VecDeque<Message>> = HashMap::new();
    for p in deep_plus {
        if let (Some(s), Some(_)) = (p.symbol(), p.time()) {
            queues.entry(s).or_default().push_back(p);
        }
    }
    let mut open: HashMap<Symbol, Episode> = HashMap::new();
    let mut per_symbol: HashMap<Symbol, (u64, u64)> = HashMap::new();

    for m in deep {
        let Some(symbol) = m.symbol() else { continue };
        let complete = level_books.entry(symbol).or_default().apply(&m);
        if !complete {
            continue;
        }
        let t = m.time().unwrap_or(i64::MIN);
        if let Some(queue) = queues.get_mut(&symbol) {
            let book = order_books.entry(symbol).or_default();
            while queue
                .front()
                .is_some_and(|p| p.time().is_some_and(|pt| pt <= t))
            {
                let p = queue.pop_front().expect("front exists");
                let pt = p.time().expect("filtered");
                let last = last_time.entry(symbol).or_insert(pt);
                if pt < *last {
                    report.deep_plus_time_regressions += 1;
                }
                *last = pt.max(*last);
                book.apply(&p);
                report.deep_plus_messages += 1;
            }
        }
        report.checkpoints += 1;
        let counts = per_symbol.entry(symbol).or_insert((0, 0));
        counts.0 += 1;
        let deep_levels = level_books[&symbol].levels();
        let empty = OrderBook::default();
        let plus_levels = order_books.get(&symbol).unwrap_or(&empty).levels();
        if deep_levels == plus_levels {
            report.full_book_equal += 1;
            report.top_of_book_equal += 1;
            if let Some(mut e) = open.remove(&symbol) {
                e.end = Some(t);
                report.episodes.push(e);
            }
            continue;
        }
        counts.1 += 1;
        if deep_levels.best() == plus_levels.best() {
            report.top_of_book_equal += 1;
        }
        let diffs = diff(deep_levels, plus_levels);
        let odd = diffs.iter().all(|d| d.deep.abs_diff(d.deep_plus) < 100);
        let e = open.entry(symbol).or_insert(Episode {
            symbol,
            start: t,
            end: None,
            checkpoints: 0,
            odd_lot_only: true,
        });
        e.checkpoints += 1;
        e.odd_lot_only &= odd;
        if report.mismatches.len() < keep_mismatches {
            report.mismatches.push(Mismatch {
                time: t,
                symbol,
                diffs,
            });
        }
    }
    report.episodes.extend(open.into_values());
    report.episodes.sort_by_key(|e| e.start);
    let mut ps: Vec<_> = per_symbol
        .into_iter()
        .map(|(s, (c, m))| (s, c, m))
        .collect();
    ps.sort_by_key(|x| x.0);
    report.per_symbol = ps;
    for b in order_books.values() {
        report.anomalies.unknown_order += b.anomalies.unknown_order;
        report.anomalies.duplicate_order += b.anomalies.duplicate_order;
        report.anomalies.overfill += b.anomalies.overfill;
    }
    report
}
