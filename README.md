# tyche-market

[![CI](https://github.com/Valkyra-Labs/tyche-market/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Valkyra-Labs/tyche-market/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Tests](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Valkyra-Labs/tyche-market/badges/tests.json)](https://github.com/Valkyra-Labs/tyche-market/actions/workflows/ci.yml)
[![wasm gzip](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Valkyra-Labs/tyche-market/badges/wasm-size.json)](https://github.com/Valkyra-Labs/tyche-market/actions/workflows/ci.yml)
[![MSRV 1.85](https://img.shields.io/badge/MSRV-1.85-blue.svg)](Cargo.toml)

The tests and wasm badges are published by CI from each green run on
`main`: tests passed in `cargo test --release` on Linux (unit,
integration and doc tests), and the gzip size (level 9) of the
WebAssembly module that CI builds with wasm-pack
(`--no-default-features --features wasm`). CI checks the MSRV with
`cargo +1.85 check`.

Order-book reconstruction and replay for IEX market data, in Rust.

tyche-market reads the pcap files IEX publishes as free historical data,
rebuilds the order book of any symbol message by message from DEEP+
(order by order), and checks it against DEEP (aggregated by price level)
for the same day: at every point where DEEP marks an event complete, the
DEEP+ book summed by price must equal the DEEP book. The same engine
compiles to WebAssembly and drives the
[tyche-replay](https://github.com/Valkyra-Labs/tyche-replay) web app.

Status: early. Measured on 2026-09-24 for AAPL, NVDA, QQQ, SPY and TSLA
(9.8 million checkpoints): the book rebuilt from DEEP+ equals DEEP at
every event end, with no unknown, duplicate or overfilled orders; the
whole day checks in 2.5 s. In the browser
([tyche-replay](https://github.com/Valkyra-Labs/tyche-replay), engine
`8f70fe5`), a full NVDA day (3 million messages) loads in about 0.3 s and
replays at 600x at 60 frames per second; that record is tyche-replay's
docs/MEASUREMENTS.md. Method, stamps and limits for the rest:
[docs/MEASUREMENTS.md](docs/MEASUREMENTS.md).

## What it does

- Reads classic pcap and pcapng, gzip or not, from a file or a stream.
- Parses IEX Transport Protocol v1 segments; detects duplicate and
  missing sequence numbers.
- Decodes DEEP (v1.08) and DEEP+ (v1.05) messages.
- Keeps an order-by-order book (add, modify, delete, execute, clear) and
  a price-level book, with counters for anything that does not fit.
- Cuts a few symbols out of a day, or out of an existing `.tyc`, into a
  small capture file for demos.
- Replays one symbol's day with seeking (a book snapshot every 20,000
  messages), the book midpoint and a liquidity heatmap. A replay has
  size limits (256 MiB of capture, 6 million messages, 10,000 resting
  orders and 5,000 price levels on the book by default, about twice the
  largest measured day and far above its deepest book), so a capture
  from an unknown source fails with a coded error instead of taking
  unbounded memory.
- Refuses damaged pcap input with an error rather than a panic, and
  records or blocks over 256 KiB before reading them.
- Runs the DEEP+ versus DEEP parity check.
- Builds to WebAssembly (`--features wasm`).

## Command line

```bash
cargo install --path . --features gzip
```

Stream a day from IEX and keep only a few symbols, without storing the
full file:

```bash
curl -s "$DEEP_PLUS_URL" | tyche extract --symbols AAPL,SPY -o day_deepplus.tyc -
```

```bash
tyche parity day_deep.tyc day_deepplus.tyc --show 5
```

Download links for each day are listed by
`https://iextrading.com/api/1.0/hist?date=YYYYMMDD`.

## Data

Data provided for free by IEX. By accessing or using IEX Historical Data,
you agree to the IEX Historical Data Terms of Use
(https://www.iex.io/legal/hist-data-terms). IEX data reflects trading on
IEX only and is not a basis for trading decisions.

## License

MIT OR Apache-2.0, at your option.
