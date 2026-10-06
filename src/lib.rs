//! Order-book reconstruction and replay for IEX market data.
//!
//! - [`pcap`]: read the pcap and pcapng files IEX publishes as HIST data.
//! - [`iextp`]: IEX Transport Protocol segments and message blocks.
//! - [`message`]: DEEP (price level) and DEEP+ (order by order) messages.
//! - [`book`]: an order-by-order book and a price-level book.
//! - [`capture`]: symbol-filtered captures small enough for a demo.
//! - [`parity`]: DEEP+ rebuilt and aggregated against DEEP, checkpoint by
//!   checkpoint.
//! - [`replay`]: one symbol's day, seekable to any moment.
//!
//! Data provided for free by IEX. By accessing or using IEX Historical
//! Data, you agree to the IEX Historical Data Terms of Use.

pub mod book;
pub mod capture;
pub mod iextp;
pub mod message;
pub mod parity;
pub mod pcap;
pub mod replay;
#[cfg(feature = "wasm")]
pub mod wasm;

pub use book::{Anomalies, LevelBook, Levels, OrderBook, Quote};
pub use message::{decode, Message, Price, Side, Symbol};

/// Errors from reading captures and feeds.
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// The input is not in the expected format.
    Format(&'static str),
    /// The input ends inside a structure.
    Truncated(&'static str),
    /// The input is larger than a [`replay::Limits`] allows.
    Limit {
        limit: Limit,
        max: usize,
    },
}

/// What a capture was too large in. Each has a stable code, which is also
/// how the error's message begins, so a caller (the web app, across the
/// WebAssembly boundary) can tell them apart without parsing prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// Bytes of the capture, once inflated: `capture_too_large`.
    CaptureBytes,
    /// Messages for the replayed symbol: `too_many_messages`.
    Messages,
    /// Price levels on the book at one time, both sides: `too_many_levels`.
    PriceLevels,
    /// Orders resting on the book at one time: `too_many_orders`.
    Orders,
}

impl Limit {
    pub fn code(self) -> &'static str {
        match self {
            Limit::CaptureBytes => "capture_too_large",
            Limit::Messages => "too_many_messages",
            Limit::PriceLevels => "too_many_levels",
            Limit::Orders => "too_many_orders",
        }
    }

    fn unit(self) -> &'static str {
        match self {
            Limit::CaptureBytes => "bytes in the capture",
            Limit::Messages => "messages for the symbol",
            Limit::PriceLevels => "price levels on the book at once",
            Limit::Orders => "orders on the book at once",
        }
    }
}

impl Error {
    /// A short stable code: `io`, `format`, `truncated`, or the
    /// [`Limit::code`] of the limit that was passed. The error's message
    /// begins with it (but for `io`).
    pub fn code(&self) -> &'static str {
        match self {
            Error::Io(_) => "io",
            Error::Format(_) => "format",
            Error::Truncated(_) => "truncated",
            Error::Limit { limit, .. } => limit.code(),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Format(what) => write!(f, "format: {what}"),
            Error::Truncated(what) => write!(f, "truncated: {what}"),
            Error::Limit { limit, max } => {
                write!(f, "{}: more than {max} {}", limit.code(), limit.unit())
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
