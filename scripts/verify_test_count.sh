#!/usr/bin/env bash
set -euo pipefail

# Script de verificación y auditoría del conteo exacto de pruebas en Capa 8 (RFC-ILP-2026)

echo "=================================================================="
echo "    ILP PROTOCOL TEST SUITE AUDIT & COUNT VERIFICATION           "
echo "=================================================================="

set +e
OUTPUT=$(cargo test --locked --all-features 2>&1)
EXIT_CODE=$?
set -e

if [ $EXIT_CODE -ne 0 ]; then
    echo "ERROR: 'cargo test --locked --all-features' falló con código $EXIT_CODE:"
    echo "$OUTPUT"
    exit 1
fi

TOTAL_PASSED=0
TOTAL_FAILED=0

echo ""
printf "%-35s %-10s\n" "TEST SUITE TARGET" "PASSED"
echo "--------------------------------------------------"

CURRENT_TARGET="unittests src/lib.rs"
while IFS= read -r line; do
    if [[ "$line" == *"Running tests/"* ]] || [[ "$line" == *"Running unittests"* ]]; then
        CURRENT_TARGET=$(echo "$line" | sed -E 's/.*Running (.*)/\1/')
    elif [[ "$line" == *"test result: ok."* ]]; then
        PASSED=$(echo "$line" | sed -nE 's/.*ok\. ([0-9]+) passed.*/\1/p')
        FAILED=$(echo "$line" | sed -nE 's/.*([0-9]+) failed.*/\1/p')
        if [ -n "$PASSED" ] && [ "$PASSED" -gt 0 ]; then
            TOTAL_PASSED=$((TOTAL_PASSED + PASSED))
            TOTAL_FAILED=$((TOTAL_FAILED + FAILED))
            
            TARGET_NAME=$(basename "$CURRENT_TARGET" | sed -E 's/-[a-f0-9]+.*//' | sed 's/out\///')
            printf "%-35s %-10s\n" "$TARGET_NAME" "$PASSED"
        fi
    fi
done <<< "$OUTPUT"

echo "--------------------------------------------------"
printf "%-35s %-10s\n" "TOTAL PRUEBAS EJECUTADAS" "$TOTAL_PASSED"
echo "=================================================="

if [ "$TOTAL_FAILED" -ne 0 ]; then
    echo "ERROR: Se detectaron $TOTAL_FAILED pruebas fallidas."
    exit 1
fi

EXPECTED_COUNT=81
if [ "$TOTAL_PASSED" -ne "$EXPECTED_COUNT" ]; then
    echo "ERROR: Auditoría fallida. Se esperaban $EXPECTED_COUNT pruebas según la especificación, pero se ejecutaron $TOTAL_PASSED."
    exit 1
fi

echo "✓ Todas las $TOTAL_PASSED pruebas pasaron exitosamente y coinciden con la especificación."
exit 0
