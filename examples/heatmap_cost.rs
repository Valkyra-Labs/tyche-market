//! Cost of a liquidity heatmap: a 10-minute window, 240 columns by 80
//! price rows, at a few times of day, on a real capture.
//!
//! cargo run --release --example heatmap_cost -- data/demo/20260924_NVDA_deepplus.tyc NVDA

use std::time::Instant;
use tyche_market::replay::Replay;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let bytes = std::fs::read(&args[0]).expect("capture");
    let t = Instant::now();
    let mut r = Replay::from_capture(&bytes, &args[1]).expect("replay");
    println!(
        "load {:.0} ms, {} messages",
        t.elapsed().as_secs_f64() * 1e3,
        r.message_count()
    );
    let window = 600e9;
    let mut costs = Vec::new();
    for frac in [0.3, 0.45, 0.6, 0.75, 0.9] {
        let at = r.duration() * frac;
        r.seek(at);
        let Some(mid) = r.mid() else { continue };
        let tick = 100; // $0.01
        let top = mid - mid % tick + 40 * tick;
        let t = Instant::now();
        let h = r.heatmap(at - window, at, 240, top, tick, 80);
        let ms = t.elapsed().as_secs_f64() * 1e3;
        let filled = h.iter().filter(|v| **v != 0.0).count();
        println!(
            "at {:.0}% of the day: {:.2} ms, {} non-empty cells of {}",
            frac * 100.0,
            ms,
            filled,
            h.len()
        );
        costs.push(ms);
    }
    costs.sort_by(f64::total_cmp);
    println!("max {:.2} ms", costs.last().copied().unwrap_or(0.0));
}
