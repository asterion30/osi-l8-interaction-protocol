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
TMP_BENCH="$(mktemp)"
trap 'rm -f "$TMP_BENCH"' EXIT

cd "$ROOT_DIR"

# Ejecutar el benchmark y verificar código de salida de forma precisa
set +e
cargo run --release --example benchmark_latency > "$TMP_BENCH" 2>&1
EXIT_CODE=$?
set -e
if [ $EXIT_CODE -ne 0 ]; then
    echo "❌ Error: El benchmark falló con código de salida $EXIT_CODE" >&2
    cat "$TMP_BENCH" >&2
    exit $EXIT_CODE
fi

CURRENT_DATE="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

cat << EOF > "$OUTPUT_FILE"
# RFC-ILP-2026: Benchmark Latency & Statistical Characterization

This document contains raw and processed micro-benchmark results for \`ilp-core\`,
characterizing median (p50), 95th percentile (p95), 99th percentile (p99), and standard deviation
across 100,000 independent operations measured in amortized batches in release mode (\`--release\`).

## Reproduction Command

\`\`\`bash
cargo run --release --example benchmark_latency
\`\`\`

## Execution Results

\`\`\`text
$(cat "$TMP_BENCH")
\`\`\`

---
*Generated automatically by \`scripts/run_benchmarks.sh\` on ${CURRENT_DATE}.*
EOF

echo "✅ Benchmark output saved to docs/BENCHMARK_RESULTS.md"
