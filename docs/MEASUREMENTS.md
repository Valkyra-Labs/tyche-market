# Measurements

Every number in the README comes from here, with its stamp. Host: Apple
M4 Pro (12 CPU cores: 8 performance, 4 efficiency), 24 GB, macOS 26.6.
Toolchain: Rust 1.98.0, release build. Data: IEX HIST for 2026-09-24,
DEEP 1.0 (`20260924_IEXTP1_DEEP1.0.pcap.gz`, 15.13 GB) and DEEP+ single
channel (`20260924_IEXTP1_DPLS1.0.pcap.gz`, 14.20 GB), streamed from
IEX's public storage and never stored whole. Symbols: AAPL, NVDA, QQQ,
SPY, TSLA.

Data provided for free by IEX. By accessing or using IEX Historical Data,
you agree to the IEX Historical Data Terms of Use.

## Extraction (build `c216ca3`)

`curl -s URL | tyche extract --symbols AAPL,SPY,TSLA,NVDA,QQQ -o OUT -`,
both feeds at once over one connection each.

| feed | packets | messages | kept (5 symbols) | missing | duplicates | wall |
|---|---|---|---|---|---|---|
| DEEP | 377,661,977 | 551,054,372 | 10,516,243 | 0 | 0 | 10,236 s |
| DEEP+ | 378,550,147 | 533,153,223 | 10,117,572 | 0 | 0 | 8,499 s |

The wall time is the download: throughput fell from about 2.4 MB/s to
about 0.7 MB/s per connection during the run. Output: 337 MB (DEEP) and
350 MB (DEEP+) of messages for the five symbols.

## Parity: DEEP+ rebuilt against DEEP (build `6b8f687`)

Method: the DEEP+ order-by-order book, summed by price, compared with the
DEEP price-level book for the same symbol at every DEEP update flagged
"event processing complete" (9,806,031 checkpoints), every level on both
sides. Alignment by timestamp within each symbol. `tyche parity`.

| measure | result |
|---|---|
| full book equal at flagged checkpoints | 9,806,029 of 9,806,031 |
| full book equal at event ends (last update with a timestamp) | 9,806,031 of 9,806,031 |
| best bid and ask (price and size) equal | 9,806,031 of 9,806,031 |
| orders referenced but never added / added twice / overfilled | 0 / 0 / 0 |
| DEEP+ timestamps going backwards within a symbol | 0 |
| wall time for the day, five symbols | 2.50 s (peak RSS 2.0 GB) |

Per symbol: AAPL 719,205 checkpoints, NVDA 2,857,938, QQQ 3,442,781,
SPY 2,732,724, TSLA 53,383.

The two flagged checkpoints that disagree (SPY at 12:57:21, NVDA at
14:23:29 ET) are DEEP updates marked complete while more updates with
the same timestamp followed, inside one event that DEEP+ shows as a
delete and an add at the same nanosecond; at the event's last update
the books agree.

What went wrong first: the first version (`33d6f7c` plus the parity
diagnostics) advanced one shared DEEP+ stream up to each checkpoint's
time. Timestamps are only ordered within a symbol, so a later message of
one symbol stalled the stream and left other symbols' messages
unapplied. It reported 99.07% agreement; the 56,397 disagreement
episodes all closed again within 0.5 ms (p99), which pointed at the
alignment, and tracing one order through both feeds confirmed it.

What this does not show: other days, other symbols, DEEP+ multi-channel
(DPLC), recovery from gaps (there were none).

## Browser replay

Moved to tyche-replay's `docs/MEASUREMENTS.md`, which measures the app
with the ladder, heatmap and trades on screen. The first reading, taken
with a ladder only (tyche-replay `e547f7b`, engine `b0e2436`): NVDA's day
loads in 315 ms and plays 10:00-11:40 ET at 600x at 60 fps, frame p95
16.9 ms, worker request p95 0.30 ms.
