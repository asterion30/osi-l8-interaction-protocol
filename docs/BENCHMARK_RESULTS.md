# RFC-ILP-2026: Benchmark Latency & Statistical Characterization

This document contains raw and processed micro-benchmark results for `ilp-core`,
characterizing median (p50), 95th percentile (p95), 99th percentile (p99), and standard deviation
across 100,000 independent operations measured in amortized batches in release mode (`--release`).

## Reproduction Command

```bash
cargo run --release --example benchmark_latency
```

## Execution Results

```text
   Compiling ilp-core v0.1.0 (/home/rober/Documentos/Capa8)
    Finished `release` profile [optimized] target(s) in 1.57s
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
    • Amortization: 100 ops per batch (1000 samples = 100000 total ops)
================================================================================

>>> Batch-Amortized Latency Distribution (1,000 batches × 100 ops/batch — ns/op):

Operation / Target                     |     Min |     p50 |     p95 |     p99 |     Max |    Mean |  StdDev
---------------------------------------------------------------------------------------------------------
1. I-PDU Header (36B Roundtrip)        |    26.9 |    26.9 |    26.9 |    26.9 |   230.3 |    27.1 |     6.4
2. I-PDU Packet (512B Wire Roundtrip)  |   112.0 |   112.6 |   112.6 |   116.0 |   751.4 |   113.6 |    21.7
3. MSAC Firewall (3-Step Inspection)   |   913.2 |   933.1 |  1224.5 |  1559.4 |  1718.7 |   976.2 |   121.2

--------------------------------------------------------------------------------
>>> RESUMEN ESTADÍSTICO PARA AUDITORÍA Y DOCUMENTACIÓN
--------------------------------------------------------------------------------

| Operation / Subsystem | Framing / Size | Median (p50) | p95 Latency | p99 Latency | Max Latency | StdDev (σ) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **I-PDU Header Parsing** | 36 Bytes (Canonical) | **26.9 ns** | 26.9 ns | 26.9 ns | 230.3 ns | ±6.4 ns |
| **I-PDU Packet Wire Roundtrip** | 512B Payload | **112.6 ns** | 112.6 ns | 116.0 ns | 751.4 ns | ±21.7 ns |
| **MSAC Semantic Firewall Egress** | Full 3 Steps | **933.1 ns** | 1224.5 ns | 1559.4 ns | 1718.7 ns | ±121.2 ns |

📌 Nota metodológica: Latencies are amortized averages across 100-operation batches to eliminate vDSO clock_gettime overhead (~15-25 ns). Individual single-op invocation latency will reflect the system clock floor.
   Los valores reflejan el overhead neto por operación en espacio de usuario.
✅ Benchmark finished successfully.
```

---
*Generated automatically by `scripts/run_benchmarks.sh` on 2026-11-08T21:15:52Z.*
