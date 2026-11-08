# RFC-ILP-2026: Benchmark Latency & Statistical Characterization

This document contains raw and processed micro-benchmark results for `ilp-core`,
characterizing median (p50), 95th percentile (p95), 99th percentile (p99), and standard deviation
across 100,000 independent samples in release mode (`--release`).

## Reproduction Command

```bash
cargo run --release --example benchmark_latency
```

## Execution Results

```text
    Finished `release` profile [optimized] target(s) in 0.06s
     Running `target/release/examples/benchmark_latency`
================================================================================
  RFC-ILP-2026: LATENCY & STATISTICAL BENCHMARK
================================================================================
  Hardware Environment:
    • CPU Model:    AMD FX(tm)-8320 Eight-Core Processor
    • CPU Cores:    8
    • Platform:     linux (x86_64)
    • Build Config: RELEASE (Optimized with LLVM)
    • Warmup Iter:  10000
    • Measured:     100000 samples per test
================================================================================

>>> DETAILED LATENCY DISTRIBUTION (Nanoseconds):

Operation / Target                     |     Min |     p50 |     p95 |     p99 |     Max |    Mean |  StdDev
---------------------------------------------------------------------------------------------------------
1. I-PDU Header (36B Roundtrip)        |      66 |      69 |      70 |      73 |   21203 |    70.2 |    81.7
2. I-PDU Packet (512B Wire Roundtrip)  |     152 |     158 |     240 |     306 |   32424 |   181.6 |   289.2
3. MSAC Firewall (3-Step Inspection)   |     931 |     979 |    1228 |    1550 |   25109 |  1022.6 |   426.2
4. Baseline JSON-RPC (512B Scan)       |     368 |     387 |     424 |     498 |   22095 |   397.7 |   251.9

--------------------------------------------------------------------------------
>>> MARKDOWN TABLE FOR README.md & AUDITORS
--------------------------------------------------------------------------------

| Operation / Subsystem | Framing / Size | Median (p50) | p95 Latency | p99 Latency | Max Latency | StdDev (σ) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **I-PDU Header Parsing** | 36 Bytes (Canonical) | **69 ns** | 70 ns | 73 ns | 21203 ns | ±81.7 ns |
| **I-PDU Packet Wire Roundtrip** | 512B Payload | **158 ns** | 240 ns | 306 ns | 32424 ns | ±289.2 ns |
| **MSAC Semantic Firewall Egress** | Full 3 Steps | **979 ns** | 1228 ns | 1550 ns | 25109 ns | ±426.2 ns |
| **JSON-RPC String Scan (Baseline)** | 512B Text | **387 ns** | 424 ns | 498 ns | 22095 ns | ±251.9 ns |

💡 Speedup factor: I-PDU header parsing achieves ~5.6x lower p50 latency than naive JSON-RPC field scanning.
✅ Benchmark finished successfully.
```

---
*Generated automatically by `scripts/run_benchmarks.sh` on $(date -u).*
