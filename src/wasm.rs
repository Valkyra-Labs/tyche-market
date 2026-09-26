//! JavaScript bindings (feature `wasm`): a replay the browser drives.
//!
//! Arrays cross the boundary as `Float64Array`s of plain numbers so the
//! caller can draw from them without allocating objects per level.

use crate::message::Side;
use crate::replay::Replay;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct TycheReplay {
    inner: Replay,
}

#[wasm_bindgen]
impl TycheReplay {
    /// Load one symbol from a DEEP+ capture file (`.tyc`).
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: &[u8], symbol: &str) -> Result<TycheReplay, JsError> {
        Replay::from_capture(bytes, symbol)
            .map(|inner| TycheReplay { inner })
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Nanoseconds from the first to the last message.
    pub fn duration(&self) -> f64 {
        self.inner.duration()
    }

    /// Epoch milliseconds of time 0.
    #[wasm_bindgen(js_name = startEpochMs)]
    pub fn start_epoch_ms(&self) -> f64 {
        self.inner.start_epoch_ns() as f64 / 1e6
    }

    #[wasm_bindgen(js_name = messageCount)]
    pub fn message_count(&self) -> u32 {
        self.inner.message_count() as u32
    }

    pub fn cursor(&self) -> u32 {
        self.inner.cursor() as u32
    }

    /// Move the book to `time` (ns since time 0); returns messages applied.
    pub fn seek(&mut self, time: f64) -> u32 {
        self.inner.seek(time) as u32
    }

    /// The best `depth` levels per side: `[bids, asks, then bid price,
    /// size pairs from the best down, then ask pairs from the best up]`.
    /// Prices are in dollars.
    pub fn levels(&self, depth: u32) -> Vec<f64> {
        let levels = self.inner.levels();
        let depth = depth as usize;
        let bids: Vec<_> = levels.bids.iter().rev().take(depth).collect();
        let asks: Vec<_> = levels.asks.iter().take(depth).collect();
        let mut out = Vec::with_capacity(2 + 2 * (bids.len() + asks.len()));
        out.push(bids.len() as f64);
        out.push(asks.len() as f64);
        for (p, s) in bids.into_iter().chain(asks) {
            out.push(*p as f64 / 10_000.0);
            out.push(*s as f64);
        }
        out
    }

    /// Executions with `from < time <= to`, flattened as
    /// `[time, price, size, side]` where side is 1 when a resting bid was
    /// hit (a sell) and -1 when a resting ask was lifted (a buy).
    pub fn executions(&self, from: f64, to: f64) -> Vec<f64> {
        let mut out = Vec::new();
        for e in self.inner.executions(from, to) {
            out.push(e.time);
            out.push(e.price as f64 / 10_000.0);
            out.push(e.size as f64);
            out.push(match e.resting_side {
                Side::Buy => 1.0,
                Side::Sell => -1.0,
            });
        }
        out
    }

    /// Liquidity heatmap over `(from, to]` (ns since time 0): `columns`
    /// time slices by `rows` prices from `top` (dollars) down in steps of
    /// `tick` (dollars); bids positive, asks negative. Column-major.
    pub fn heatmap(
        &self,
        from: f64,
        to: f64,
        columns: u32,
        top: f64,
        tick: f64,
        rows: u32,
    ) -> Vec<f32> {
        let to_price = |d: f64| (d * 10_000.0).round() as i64;
        self.inner.heatmap(
            from,
            to,
            columns as usize,
            to_price(top),
            to_price(tick),
            rows as usize,
        )
    }

    /// Midpoint of the best bid and ask in dollars (NaN when one side is
    /// empty).
    pub fn mid(&self) -> f64 {
        self.inner
            .mid()
            .map(|p| p as f64 / 10_000.0)
            .unwrap_or(f64::NAN)
    }

    /// Orders resting on the book now.
    #[wasm_bindgen(js_name = orderCount)]
    pub fn order_count(&self) -> u32 {
        self.inner.book().order_count() as u32
    }
}
