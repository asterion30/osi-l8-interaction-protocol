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
    Finished `release` profile [optimized] target(s) in 1.40s
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

>>> OVERHEAD ABSOLUTO DEL MONITOR EN ESPACIO DE USUARIO (ns/op):

Operation / Target                     |     Min |     p50 |     p95 |     p99 |     Max |    Mean |  StdDev
---------------------------------------------------------------------------------------------------------
1. I-PDU Header (36B Roundtrip)        |    26.9 |    26.9 |    26.9 |    26.9 |   284.1 |    27.2 |     8.1
2. I-PDU Packet (512B Wire Roundtrip)  |   112.6 |   112.6 |   127.0 |   178.3 |   579.2 |   116.2 |    25.9
3. MSAC Firewall (3-Step Inspection)   |   886.5 |   908.6 |  1230.6 |  1455.8 |  1691.0 |   964.2 |   120.2
4. Baseline JSON-RPC (512B Scan)       |   321.9 |   345.3 |   372.1 |   557.6 |   903.0 |   349.3 |    41.3

--------------------------------------------------------------------------------
>>> RESUMEN ESTADÍSTICO PARA AUDITORÍA Y DOCUMENTACIÓN
--------------------------------------------------------------------------------

| Operation / Subsystem | Framing / Size | Median (p50) | p95 Latency | p99 Latency | Max Latency | StdDev (σ) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **I-PDU Header Parsing** | 36 Bytes (Canonical) | **26.9 ns** | 26.9 ns | 26.9 ns | 284.1 ns | ±8.1 ns |
| **I-PDU Packet Wire Roundtrip** | 512B Payload | **112.6 ns** | 127.0 ns | 178.3 ns | 579.2 ns | ±25.9 ns |
| **MSAC Semantic Firewall Egress** | Full 3 Steps | **908.6 ns** | 1230.6 ns | 1455.8 ns | 1691.0 ns | ±120.2 ns |
| **JSON-RPC String Scan (Baseline)** | 512B Text | **345.3 ns** | 372.1 ns | 557.6 ns | 903.0 ns | ±41.3 ns |

📌 Nota metodológica: Mediciones amortizadas en lotes de 100 operaciones para eliminar el artefacto del reloj (vDSO clock_gettime).
   Los valores reflejan el overhead neto por operación en espacio de usuario.
✅ Benchmark finished successfully.
```

---
*Generated automatically by `scripts/run_benchmarks.sh` on 2026-11-08T17:03:30Z.*
