#!/usr/bin/env bash
set -euo pipefail

echo "============================================================"
echo " Running RFC-ILP-2026 Micro-Benchmarks in Release Mode..."
echo "============================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
DOCS_DIR="$ROOT_DIR/docs"

mkdir -p "$DOCS_DIR"

OUTPUT_FILE="$DOCS_DIR/BENCHMARK_RESULTS.md"

cat << 'EOF' > "$OUTPUT_FILE"
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
EOF

cd "$ROOT_DIR"
cargo run --release --example benchmark_latency >> "$OUTPUT_FILE" 2>&1

cat << 'EOF' >> "$OUTPUT_FILE"
```

---
*Generated automatically by `scripts/run_benchmarks.sh` on $(date -u).*
EOF

echo "✅ Benchmark output saved to docs/BENCHMARK_RESULTS.md"
