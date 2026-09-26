//! Decoded DEEP (0x8004) and DEEP+ (0x8005) messages.
//!
//! Layouts follow the IEX DEEP Specification v1.08 and the IEX DEEP+
//! Specification v1.05: little endian, prices as signed 64-bit integers
//! with four implied decimals, timestamps as nanoseconds since the Unix
//! epoch. IEX may lengthen messages or add types without notice, so a
//! message is accepted when it is at least as long as its layout, and
//! unknown types decode to [`Message::Other`].

use crate::iextp::{PROTOCOL_DEEP, PROTOCOL_DEEP_PLUS};
use std::fmt;

/// Price with four implied decimals (123400 = $12.34).
pub type Price = i64;

/// A security identifier: eight ASCII bytes, space padded.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Symbol(pub [u8; 8]);

impl Symbol {
    pub fn new(s: &str) -> Self {
        let mut b = [b' '; 8];
        for (d, c) in b.iter_mut().zip(s.bytes()) {
            *d = c;
        }
        Symbol(b)
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or("").trim_end()
    }
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Symbol({})", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Side {
    Buy,
    Sell,
}

/// One decoded message. Only the fields needed for book building,
/// parity and replay are kept; the rest decode to [`Message::Other`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Message {
    /// 'S': start or end of messages, system hours, regular hours.
    SystemEvent { time: i64, event: u8 },
    /// 'H': trading status for a symbol ('H' halted, 'O' order acceptance,
    /// 'P' paused, 'T' trading).
    TradingStatus {
        time: i64,
        symbol: Symbol,
        status: u8,
    },
    /// 'E': security event (opening or closing process complete).
    SecurityEvent {
        time: i64,
        symbol: Symbol,
        event: u8,
    },
    /// DEEP '8' / '5': aggregate displayed size at a price level; size 0
    /// removes the level. `complete` is the Event Flags bit: the book is
    /// consistent after this message.
    PriceLevel {
        side: Side,
        complete: bool,
        time: i64,
        symbol: Symbol,
        size: u32,
        price: Price,
    },
    /// DEEP+ 'a': a displayed order added to the book.
    AddOrder {
        side: Side,
        time: i64,
        symbol: Symbol,
        order_id: i64,
        size: u32,
        price: Price,
    },
    /// DEEP+ 'M': new total size and price of an order.
    OrderModify {
        keeps_priority: bool,
        time: i64,
        symbol: Symbol,
        order_id: i64,
        size: u32,
        price: Price,
    },
    /// DEEP+ 'R': an order removed from the book.
    OrderDelete {
        time: i64,
        symbol: Symbol,
        order_id: i64,
    },
    /// DEEP+ 'L': an execution against a displayed order. `price` is the
    /// execution price, which may differ from the booked price.
    OrderExecuted {
        time: i64,
        symbol: Symbol,
        order_id: i64,
        size: u32,
        price: Price,
        trade_id: i64,
    },
    /// 'T': a trade that does not change displayed size (DEEP: every trade
    /// report; DEEP+: non-displayed against non-displayed).
    Trade {
        time: i64,
        symbol: Symbol,
        size: u32,
        price: Price,
        trade_id: i64,
    },
    /// 'B': a trade broken the same day.
    TradeBreak {
        time: i64,
        symbol: Symbol,
        trade_id: i64,
    },
    /// DEEP+ 'C': the book for a symbol was cleared.
    ClearBook { time: i64, symbol: Symbol },
    /// Any other or unknown type.
    Other { kind: u8 },
}

fn i64_at(b: &[u8], at: usize) -> i64 {
    i64::from_le_bytes(b[at..at + 8].try_into().expect("8 bytes"))
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}

fn symbol_at(b: &[u8], at: usize) -> Symbol {
    Symbol(b[at..at + 8].try_into().expect("8 bytes"))
}

fn side(b: u8) -> Option<Side> {
    match b {
        b'8' => Some(Side::Buy),
        b'5' => Some(Side::Sell),
        _ => None,
    }
}

/// Decode one message of the given protocol. A message shorter than its
/// layout, or a side byte outside the specification, decodes to
/// [`Message::Other`] with its type byte, so a damaged message cannot
/// silently change the book.
pub fn decode(protocol: u16, m: &[u8]) -> Message {
    let Some(&kind) = m.first() else {
        return Message::Other { kind: 0 };
    };
    let other = Message::Other { kind };
    let need = |n: usize| m.len() >= n;
    match (protocol, kind) {
        (_, b'S') if need(10) => Message::SystemEvent {
            time: i64_at(m, 2),
            event: m[1],
        },
        (_, b'H') if need(18) => Message::TradingStatus {
            time: i64_at(m, 2),
            symbol: symbol_at(m, 10),
            status: m[1],
        },
        (_, b'E') if need(18) => Message::SecurityEvent {
            time: i64_at(m, 2),
            symbol: symbol_at(m, 10),
            event: m[1],
        },
        (_, b'T') if need(38) => Message::Trade {
            time: i64_at(m, 2),
            symbol: symbol_at(m, 10),
            size: u32_at(m, 18),
            price: i64_at(m, 22),
            trade_id: i64_at(m, 30),
        },
        (_, b'B') if need(38) => Message::TradeBreak {
            time: i64_at(m, 2),
            symbol: symbol_at(m, 10),
            trade_id: i64_at(m, 30),
        },
        (PROTOCOL_DEEP, b'8' | b'5') if need(30) => Message::PriceLevel {
            side: side(kind).expect("matched"),
            complete: m[1] & 1 == 1,
            time: i64_at(m, 2),
            symbol: symbol_at(m, 10),
            size: u32_at(m, 18),
            price: i64_at(m, 22),
        },
        (PROTOCOL_DEEP_PLUS, b'a') if need(38) => match side(m[1]) {
            Some(side) => Message::AddOrder {
                side,
                time: i64_at(m, 2),
                symbol: symbol_at(m, 10),
                order_id: i64_at(m, 18),
                size: u32_at(m, 26),
                price: i64_at(m, 30),
            },
            None => other,
        },
        (PROTOCOL_DEEP_PLUS, b'M') if need(38) => Message::OrderModify {
            keeps_priority: m[1] & 1 == 1,
            time: i64_at(m, 2),
            symbol: symbol_at(m, 10),
            order_id: i64_at(m, 18),
            size: u32_at(m, 26),
            price: i64_at(m, 30),
        },
        (PROTOCOL_DEEP_PLUS, b'R') if need(26) => Message::OrderDelete {
            time: i64_at(m, 2),
            symbol: symbol_at(m, 10),
            order_id: i64_at(m, 18),
        },
        (PROTOCOL_DEEP_PLUS, b'L') if need(46) => Message::OrderExecuted {
            time: i64_at(m, 2),
            symbol: symbol_at(m, 10),
            order_id: i64_at(m, 18),
            size: u32_at(m, 26),
            price: i64_at(m, 30),
            trade_id: i64_at(m, 38),
        },
        (PROTOCOL_DEEP_PLUS, b'C') if need(18) => Message::ClearBook {
            time: i64_at(m, 2),
            symbol: symbol_at(m, 10),
        },
        _ => other,
    }
}

impl Message {
    /// The symbol a message refers to, if any.
    pub fn symbol(&self) -> Option<Symbol> {
        match *self {
            Message::TradingStatus { symbol, .. }
            | Message::SecurityEvent { symbol, .. }
            | Message::PriceLevel { symbol, .. }
            | Message::AddOrder { symbol, .. }
            | Message::OrderModify { symbol, .. }
            | Message::OrderDelete { symbol, .. }
            | Message::OrderExecuted { symbol, .. }
            | Message::Trade { symbol, .. }
            | Message::TradeBreak { symbol, .. }
            | Message::ClearBook { symbol, .. } => Some(symbol),
            Message::SystemEvent { .. } | Message::Other { .. } => None,
        }
    }

    /// The event timestamp, if the message carries one.
    pub fn time(&self) -> Option<i64> {
        match *self {
            Message::SystemEvent { time, .. }
            | Message::TradingStatus { time, .. }
            | Message::SecurityEvent { time, .. }
            | Message::PriceLevel { time, .. }
            | Message::AddOrder { time, .. }
            | Message::OrderModify { time, .. }
            | Message::OrderDelete { time, .. }
            | Message::OrderExecuted { time, .. }
            | Message::Trade { time, .. }
            | Message::TradeBreak { time, .. }
            | Message::ClearBook { time, .. } => Some(time),
            Message::Other { .. } => None,
        }
    }
}

/// Symbol bytes of a raw message without decoding it (for filtering at
/// capture speed): every symbol-bearing message in both protocols keeps
/// the symbol at offset 10.
pub fn raw_symbol(m: &[u8]) -> Option<[u8; 8]> {
    match m.first()? {
        b'S' => None,
        _ => m.get(10..18)?.try_into().ok(),
    }
}
