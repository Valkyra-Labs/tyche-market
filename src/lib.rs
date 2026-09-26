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
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Format(what) => write!(f, "format: {what}"),
            Error::Truncated(what) => write!(f, "truncated: {what}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
