//! Replay of one symbol's DEEP+ day: the order book at any moment, and
//! the executions in any time window.
//!
//! Seeking forward applies messages; seeking backward restarts from the
//! nearest snapshot before the target (a copy of the book taken every
//! `SNAPSHOT_EVERY` messages), so any seek costs at most that many
//! messages.
//!
//! Times in this API are nanoseconds since the first message of the
//! capture, as `f64` (a trading day is about 6e13 ns, well inside the
//! 2^53 range where `f64` is exact), so a JavaScript caller loses nothing.

use crate::book::{Levels, OrderBook};
use crate::capture::Capture;
use crate::iextp::PROTOCOL_DEEP_PLUS;
use crate::message::{decode, Message, Price, Side, Symbol};
use crate::{Error, Limit};

/// Messages between book snapshots.
pub const SNAPSHOT_EVERY: usize = 20_000;

/// How large a capture a replay accepts, so that a capture from anywhere
/// (the web app loads one by URL) cannot take unbounded memory and time.
/// Past a limit, building the replay stops with [`Error::Limit`].
///
/// The defaults are about twice the largest day measured (QQQ on
/// 2026-09-24: 119.9 MB, 3,483,073 messages) and far above the deepest
/// book seen that day (159 orders, 93 price levels). The book caps also
/// bound the snapshots taken every [`SNAPSHOT_EVERY`] messages, which
/// would otherwise grow with the square of a book that only grows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Bytes of the capture, once inflated.
    pub capture_bytes: usize,
    /// Messages for the replayed symbol.
    pub messages: usize,
    /// Price levels on the book at one time, both sides together.
    pub price_levels: usize,
    /// Orders resting on the book at one time.
    pub orders: usize,
}

impl Limits {
    /// No limit at all, for captures the caller trusts.
    pub const NONE: Limits = Limits {
        capture_bytes: usize::MAX,
        messages: usize::MAX,
        price_levels: usize::MAX,
        orders: usize::MAX,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            capture_bytes: 256 << 20,
            messages: 6_000_000,
            price_levels: 5_000,
            orders: 10_000,
        }
    }
}

/// One execution against a displayed order.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Execution {
    /// Nanoseconds since the start of the capture.
    pub time: f64,
    pub price: Price,
    pub size: u32,
    /// Side of the resting order that was hit (Buy: a seller took the bid).
    pub resting_side: Side,
}

pub struct Replay {
    symbol: Symbol,
    start: i64,
    messages: Vec<Message>,
    times: Vec<f64>,
    executions: Vec<Execution>,
    snapshots: Vec<(usize, OrderBook)>,
    book: OrderBook,
    /// Messages applied to `book`.
    cursor: usize,
}

impl Replay {
    /// Build a replay of `symbol` from a DEEP+ capture.
    /// Build a replay of `symbol` from a DEEP+ capture, within the default
    /// [`Limits`].
    pub fn from_capture(bytes: &[u8], symbol: &str) -> Result<Self, Error> {
        Self::from_capture_with(bytes, symbol, &Limits::default())
    }

    /// Build a replay of `symbol` from a DEEP+ capture, within `limits`.
    pub fn from_capture_with(bytes: &[u8], symbol: &str, limits: &Limits) -> Result<Self, Error> {
        if bytes.len() > limits.capture_bytes {
            return Err(Error::Limit {
                limit: Limit::CaptureBytes,
                max: limits.capture_bytes,
            });
        }
        let cap = Capture::parse(bytes)?;
        if cap.protocol != PROTOCOL_DEEP_PLUS {
            return Err(Error::Format("replay needs a DEEP+ capture"));
        }
        let symbol = Symbol::new(symbol);
        let mut messages = Vec::new();
        for raw in cap.messages() {
            let m = decode(cap.protocol, raw?);
            if m.symbol() == Some(symbol) && m.time().is_some() {
                if messages.len() == limits.messages {
                    return Err(Error::Limit {
                        limit: Limit::Messages,
                        max: limits.messages,
                    });
                }
                messages.push(m);
            }
        }
        if messages.is_empty() {
            return Err(Error::Format("no messages for this symbol"));
        }
        Self::from_messages_with(symbol, messages, limits)
    }

    /// A replay of messages the caller trusts, with no limits.
    pub fn from_messages(symbol: Symbol, messages: Vec<Message>) -> Self {
        match Self::from_messages_with(symbol, messages, &Limits::NONE) {
            Ok(replay) => replay,
            Err(_) => unreachable!("no limit to pass"),
        }
    }

    /// A replay of `messages`, refused when they pass `limits`.
    pub fn from_messages_with(
        symbol: Symbol,
        messages: Vec<Message>,
        limits: &Limits,
    ) -> Result<Self, Error> {
        if messages.len() > limits.messages {
            return Err(Error::Limit {
                limit: Limit::Messages,
                max: limits.messages,
            });
        }
        let start = messages.iter().filter_map(Message::time).min().unwrap_or(0);
        let times: Vec<f64> = messages
            .iter()
            .map(|m| (m.time().unwrap_or(start) - start) as f64)
            .collect();
        // One pass to index executions and take snapshots.
        let mut book = OrderBook::default();
        let mut snapshots = vec![(0, OrderBook::default())];
        let mut executions = Vec::new();
        for (i, m) in messages.iter().enumerate() {
            if let Message::OrderExecuted {
                order_id,
                size,
                price,
                ..
            } = *m
            {
                if let Some(side) = book.side_of(order_id) {
                    executions.push(Execution {
                        time: times[i],
                        price,
                        size,
                        resting_side: side,
                    });
                }
            }
            book.apply(m);
            if book.order_count() > limits.orders {
                return Err(Error::Limit {
                    limit: Limit::Orders,
                    max: limits.orders,
                });
            }
            let levels = book.levels();
            if levels.bids.len() + levels.asks.len() > limits.price_levels {
                return Err(Error::Limit {
                    limit: Limit::PriceLevels,
                    max: limits.price_levels,
                });
            }
            if (i + 1) % SNAPSHOT_EVERY == 0 {
                snapshots.push((i + 1, book.clone()));
            }
        }
        Ok(Self {
            symbol,
            start,
            messages,
            times,
            executions,
            snapshots,
            book: OrderBook::default(),
            cursor: 0,
        })
    }

    pub fn symbol(&self) -> Symbol {
        self.symbol
    }

    /// Epoch nanoseconds of time 0.
    pub fn start_epoch_ns(&self) -> i64 {
        self.start
    }

    /// Time of the last message.
    pub fn duration(&self) -> f64 {
        self.times.last().copied().unwrap_or(0.0)
    }

    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    /// Messages applied so far.
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Put the book at `time`: every message with a time at or before it
    /// applied, none after. Returns the number of messages applied.
    pub fn seek(&mut self, time: f64) -> usize {
        let target = self.times.partition_point(|t| *t <= time);
        if target < self.cursor {
            let (at, snap) = self
                .snapshots
                .iter()
                .rev()
                .find(|(at, _)| *at <= target)
                .expect("snapshot 0 exists");
            self.book = snap.clone();
            self.cursor = *at;
        }
        let from = self.cursor;
        for m in &self.messages[self.cursor..target] {
            self.book.apply(m);
        }
        self.cursor = target;
        target - from
    }

    pub fn levels(&self) -> &Levels {
        self.book.levels()
    }

    pub fn book(&self) -> &OrderBook {
        &self.book
    }

    /// Executions with `from < time <= to`.
    pub fn executions(&self, from: f64, to: f64) -> &[Execution] {
        let a = self.executions.partition_point(|e| e.time <= from);
        let b = self.executions.partition_point(|e| e.time <= to);
        &self.executions[a..b]
    }

    pub fn all_executions(&self) -> &[Execution] {
        &self.executions
    }

    /// Displayed liquidity over time: the window `(from, to]` split into
    /// `columns` equal slices; for each slice, the book at the slice's end,
    /// sampled at `rows` prices `top, top - tick, ...` (top row first).
    /// Bid sizes are positive, ask sizes negative. Runs on its own copy of
    /// the book, so the replay's position does not move.
    pub fn heatmap(
        &self,
        from: f64,
        to: f64,
        columns: usize,
        top: Price,
        tick: Price,
        rows: usize,
    ) -> Vec<f32> {
        let mut out = vec![0f32; columns * rows];
        if columns == 0 || rows == 0 || to <= from || tick <= 0 {
            return out;
        }
        let start = self.times.partition_point(|t| *t <= from);
        let (at, snap) = self
            .snapshots
            .iter()
            .rev()
            .find(|(at, _)| *at <= start)
            .expect("snapshot 0 exists");
        let mut book = snap.clone();
        let mut cursor = *at;
        let step = (to - from) / columns as f64;
        for col in 0..columns {
            let edge = from + step * (col + 1) as f64;
            let end = self.times.partition_point(|t| *t <= edge);
            for m in &self.messages[cursor..end] {
                book.apply(m);
            }
            cursor = end;
            let levels = book.levels();
            for row in 0..rows {
                let price = top - tick * row as i64;
                let cell = &mut out[col * rows + row];
                if let Some(size) = levels.bids.get(&price) {
                    *cell = *size as f32;
                } else if let Some(size) = levels.asks.get(&price) {
                    *cell = -(*size as f32);
                }
            }
        }
        out
    }

    /// Midpoint of the best bid and ask at the replay's position, if both
    /// exist.
    pub fn mid(&self) -> Option<Price> {
        match self.book.levels().best() {
            (Some((b, _)), Some((a, _))) => Some((a + b) / 2),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{MAGIC, VERSION};

    /// A DEEP+ capture of `adds` AddOrder messages for ZIEXT, as the web
    /// app receives it: header, then length-prefixed messages.
    fn capture_of(adds: &[(i64, i64, Side, u32, Price)]) -> Vec<u8> {
        let mut b = MAGIC.to_vec();
        b.extend(VERSION.to_le_bytes());
        b.extend(PROTOCOL_DEEP_PLUS.to_le_bytes());
        b.extend([0; 4]);
        for &(time, id, side, size, price) in adds {
            let mut m = vec![b'a', if side == Side::Buy { b'8' } else { b'5' }];
            m.extend(time.to_le_bytes());
            m.extend(Symbol::new("ZIEXT").0);
            m.extend(id.to_le_bytes());
            m.extend(size.to_le_bytes());
            m.extend(price.to_le_bytes());
            b.extend((m.len() as u16).to_le_bytes());
            b.extend(m);
        }
        b
    }

    fn limit_of(result: Result<Replay, Error>) -> Option<(Limit, usize)> {
        match result {
            Err(Error::Limit { limit, max }) => Some((limit, max)),
            _ => None,
        }
    }

    /// `n` orders on distinct prices, one per message, never removed.
    fn distinct_adds(n: i64) -> Vec<(i64, i64, Side, u32, Price)> {
        (0..n)
            .map(|i| (1_000 + i, i, Side::Buy, 100, 1_000_000 + i * 100))
            .collect()
    }

    #[test]
    fn a_capture_over_the_byte_limit_is_refused_with_its_code() {
        let bytes = capture_of(&distinct_adds(10));
        let limits = Limits {
            capture_bytes: bytes.len() - 1,
            ..Limits::default()
        };
        let err = Replay::from_capture_with(&bytes, "ZIEXT", &limits).err();
        let err = err.expect("refused");
        assert_eq!(err.code(), "capture_too_large");
        assert!(err.to_string().starts_with("capture_too_large: "), "{err}");
        let limits = Limits {
            capture_bytes: bytes.len(),
            ..Limits::default()
        };
        assert!(Replay::from_capture_with(&bytes, "ZIEXT", &limits).is_ok());
    }

    #[test]
    fn more_messages_than_the_limit_are_refused() {
        let bytes = capture_of(&distinct_adds(10));
        let limits = Limits {
            messages: 9,
            ..Limits::default()
        };
        let got = limit_of(Replay::from_capture_with(&bytes, "ZIEXT", &limits));
        assert_eq!(got, Some((Limit::Messages, 9)));
    }

    #[test]
    fn more_resting_orders_than_the_limit_are_refused() {
        // One price, so only the order count grows.
        let adds: Vec<_> = (0..10)
            .map(|i| (1_000 + i, i, Side::Sell, 100, 1_000_000))
            .collect();
        let limits = Limits {
            orders: 9,
            ..Limits::default()
        };
        let got = limit_of(Replay::from_capture_with(
            &capture_of(&adds),
            "ZIEXT",
            &limits,
        ));
        assert_eq!(got, Some((Limit::Orders, 9)));
        assert_eq!(
            Error::Limit {
                limit: Limit::Orders,
                max: 9
            }
            .code(),
            "too_many_orders"
        );
    }

    #[test]
    fn more_price_levels_than_the_limit_are_refused() {
        let limits = Limits {
            price_levels: 9,
            ..Limits::default()
        };
        let got = limit_of(Replay::from_capture_with(
            &capture_of(&distinct_adds(10)),
            "ZIEXT",
            &limits,
        ));
        assert_eq!(got, Some((Limit::PriceLevels, 9)));
    }

    #[test]
    fn a_book_that_only_grows_stops_at_the_default_limit_at_once() {
        // A million orders never removed: before the limits this took tens
        // of seconds and gigabytes in book snapshots.
        let bytes = capture_of(&distinct_adds(1_000_000));
        let started = std::time::Instant::now();
        let err = Replay::from_capture(&bytes, "ZIEXT")
            .err()
            .expect("refused");
        assert!(
            matches!(err.code(), "too_many_orders" | "too_many_levels"),
            "{err}"
        );
        assert!(
            started.elapsed().as_secs_f64() < 5.0,
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn the_default_limits_hold_a_day_as_the_engine_sees_it() {
        // About twice the largest day measured (QQQ on 2026-09-24: 119.9 MB,
        // 3,483,073 messages; at most 159 orders and 93 price levels on
        // one book, NVDA and AAPL).
        let d = Limits::default();
        assert!(d.capture_bytes >= 240_000_000);
        assert!(d.messages >= 6_000_000);
        assert!(d.orders >= 10 * 159 && d.price_levels >= 10 * 93);
    }

    fn add(t: i64, id: i64, side: Side, size: u32, price: Price) -> Message {
        Message::AddOrder {
            side,
            time: t,
            symbol: Symbol::new("ZIEXT"),
            order_id: id,
            size,
            price,
        }
    }

    #[test]
    fn heatmap_samples_the_book_at_each_column_without_moving_the_replay() {
        let messages = vec![
            add(10, 1, Side::Buy, 100, 1_000_000),
            add(20, 2, Side::Sell, 50, 1_000_100),
            add(30, 3, Side::Buy, 70, 999_900),
        ];
        let mut r = Replay::from_messages(Symbol::new("ZIEXT"), messages);
        r.seek(15.0);
        // Times are relative to the first message (10): 0, 10, 20.
        let h = r.heatmap(0.0, 20.0, 2, 1_000_100, 100, 3);
        // Column 0 ends at 10: order 1 and order 2 on the book.
        assert_eq!(&h[0..3], &[-50.0, 100.0, 0.0]);
        // Column 1 ends at 20: order 3 added at 999,900.
        assert_eq!(&h[3..6], &[-50.0, 100.0, 70.0]);
        assert_eq!(r.cursor(), 2, "replay position unchanged");
    }

    #[test]
    fn seeking_backward_equals_replaying_from_the_start() {
        let mut messages = Vec::new();
        for i in 0..(SNAPSHOT_EVERY as i64 * 3 + 17) {
            messages.push(add(
                1_000 + i,
                i,
                Side::Buy,
                100,
                1_000_000 + (i % 50) * 100,
            ));
        }
        let mut r = Replay::from_messages(Symbol::new("ZIEXT"), messages.clone());
        r.seek(r.duration());
        let target = (SNAPSHOT_EVERY as f64) * 1.5;
        r.seek(target);
        let mut fresh = Replay::from_messages(Symbol::new("ZIEXT"), messages);
        fresh.seek(target);
        assert_eq!(r.levels(), fresh.levels());
        assert_eq!(r.cursor(), fresh.cursor());
    }
}
