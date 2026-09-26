//! Books: order-by-order (from DEEP+) and by price level (from DEEP).
//!
//! Both expose the same aggregated view, displayed size per price per
//! side, so the parity check can compare them directly.

use crate::message::{Message, Price, Side};
use std::collections::{BTreeMap, HashMap};

/// A price and the displayed size at it.
pub type Quote = (Price, u64);

/// Displayed size per price, one map per side.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Levels {
    pub bids: BTreeMap<Price, u64>,
    pub asks: BTreeMap<Price, u64>,
}

impl Levels {
    fn side_mut(&mut self, side: Side) -> &mut BTreeMap<Price, u64> {
        match side {
            Side::Buy => &mut self.bids,
            Side::Sell => &mut self.asks,
        }
    }

    fn add(&mut self, side: Side, price: Price, size: u64) {
        if size > 0 {
            *self.side_mut(side).entry(price).or_insert(0) += size;
        }
    }

    /// Subtract; returns false when the level held less than `size`.
    fn sub(&mut self, side: Side, price: Price, size: u64) -> bool {
        let levels = self.side_mut(side);
        match levels.get_mut(&price) {
            Some(v) if *v >= size => {
                *v -= size;
                if *v == 0 {
                    levels.remove(&price);
                }
                true
            }
            _ => false,
        }
    }

    /// Best bid (highest) and best ask (lowest).
    pub fn best(&self) -> (Option<Quote>, Option<Quote>) {
        (
            self.bids.iter().next_back().map(|(p, s)| (*p, *s)),
            self.asks.iter().next().map(|(p, s)| (*p, *s)),
        )
    }

    pub fn clear(&mut self) {
        self.bids.clear();
        self.asks.clear();
    }
}

#[derive(Debug, Clone, Copy)]
struct Order {
    side: Side,
    price: Price,
    size: u64,
}

/// Counters of messages that did not fit the book: each is either a feed
/// oddity or a bug, and the parity report shows them.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Anomalies {
    /// Modify, delete or execute for an order id the book does not hold.
    pub unknown_order: u64,
    /// Add for an order id already on the book.
    pub duplicate_order: u64,
    /// Execution larger than the order's remaining size.
    pub overfill: u64,
}

/// Order-by-order book for one symbol, built from DEEP+ messages.
#[derive(Debug, Default, Clone)]
pub struct OrderBook {
    orders: HashMap<i64, Order>,
    levels: Levels,
    pub anomalies: Anomalies,
}

impl OrderBook {
    pub fn levels(&self) -> &Levels {
        &self.levels
    }

    pub fn order_count(&self) -> usize {
        self.orders.len()
    }

    /// Side of a resting order, if it is on the book.
    pub fn side_of(&self, order_id: i64) -> Option<Side> {
        self.orders.get(&order_id).map(|o| o.side)
    }

    /// Apply one DEEP+ message; messages that do not change displayed
    /// size are ignored.
    pub fn apply(&mut self, m: &Message) {
        match *m {
            Message::AddOrder {
                side,
                order_id,
                size,
                price,
                ..
            } => {
                let order = Order {
                    side,
                    price,
                    size: size as u64,
                };
                if let Some(old) = self.orders.insert(order_id, order) {
                    self.anomalies.duplicate_order += 1;
                    self.levels.sub(old.side, old.price, old.size);
                }
                self.levels.add(side, price, size as u64);
            }
            Message::OrderModify {
                order_id,
                size,
                price,
                ..
            } => match self.orders.get_mut(&order_id) {
                Some(o) => {
                    self.levels.sub(o.side, o.price, o.size);
                    o.price = price;
                    o.size = size as u64;
                    let (side, size) = (o.side, o.size);
                    if size == 0 {
                        self.orders.remove(&order_id);
                    } else {
                        self.levels.add(side, price, size);
                    }
                }
                None => self.anomalies.unknown_order += 1,
            },
            Message::OrderDelete { order_id, .. } => match self.orders.remove(&order_id) {
                Some(o) => {
                    self.levels.sub(o.side, o.price, o.size);
                }
                None => self.anomalies.unknown_order += 1,
            },
            Message::OrderExecuted { order_id, size, .. } => {
                let size = size as u64;
                match self.orders.get_mut(&order_id) {
                    Some(o) => {
                        // Displayed size leaves at the booked price, whatever
                        // the execution price was.
                        let filled = if size > o.size {
                            self.anomalies.overfill += 1;
                            o.size
                        } else {
                            size
                        };
                        let (side, price) = (o.side, o.price);
                        o.size -= filled;
                        if o.size == 0 {
                            self.orders.remove(&order_id);
                        }
                        self.levels.sub(side, price, filled);
                    }
                    None => self.anomalies.unknown_order += 1,
                }
            }
            Message::ClearBook { .. } => {
                self.orders.clear();
                self.levels.clear();
            }
            _ => {}
        }
    }
}

/// Price-level book for one symbol, built from DEEP messages.
#[derive(Debug, Default, Clone)]
pub struct LevelBook {
    levels: Levels,
}

impl LevelBook {
    pub fn levels(&self) -> &Levels {
        &self.levels
    }

    /// Apply one DEEP message; returns true when the message completes an
    /// event (the book is consistent and may be compared).
    pub fn apply(&mut self, m: &Message) -> bool {
        if let Message::PriceLevel {
            side,
            complete,
            size,
            price,
            ..
        } = *m
        {
            let levels = self.levels.side_mut(side);
            if size == 0 {
                levels.remove(&price);
            } else {
                levels.insert(price, size as u64);
            }
            return complete;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Symbol;

    fn add(id: i64, side: Side, size: u32, price: Price) -> Message {
        Message::AddOrder {
            side,
            time: 0,
            symbol: Symbol::new("ZIEXT"),
            order_id: id,
            size,
            price,
        }
    }

    #[test]
    fn orders_aggregate_into_levels_and_leave_at_the_booked_price() {
        let mut b = OrderBook::default();
        b.apply(&add(1, Side::Buy, 100, 990_500));
        b.apply(&add(2, Side::Buy, 200, 990_500));
        b.apply(&add(3, Side::Sell, 50, 991_000));
        assert_eq!(b.levels().bids[&990_500], 300);
        // Executed at an improved price: size still leaves 99.05.
        b.apply(&Message::OrderExecuted {
            time: 0,
            symbol: Symbol::new("ZIEXT"),
            order_id: 1,
            size: 100,
            price: 990_700,
            trade_id: 7,
        });
        assert_eq!(b.levels().bids[&990_500], 200);
        assert_eq!(b.order_count(), 2);
        // Modify moves the order to a new price.
        b.apply(&Message::OrderModify {
            keeps_priority: false,
            time: 0,
            symbol: Symbol::new("ZIEXT"),
            order_id: 2,
            size: 150,
            price: 990_600,
        });
        assert!(!b.levels().bids.contains_key(&990_500));
        assert_eq!(b.levels().bids[&990_600], 150);
        b.apply(&Message::OrderDelete {
            time: 0,
            symbol: Symbol::new("ZIEXT"),
            order_id: 3,
        });
        assert!(b.levels().asks.is_empty());
        b.apply(&Message::OrderDelete {
            time: 0,
            symbol: Symbol::new("ZIEXT"),
            order_id: 99,
        });
        assert_eq!(b.anomalies.unknown_order, 1);
    }
}
