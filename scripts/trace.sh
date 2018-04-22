#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for KTEST in traces/*.ktest; do
  DEHAVOCED_KTEST="$KTEST.dehavoced"
  TRACE="${KTEST%.*}.instructions"

  if [ ! -f "$TRACE" ]; then
    echo "Processing $KTEST -> $TRACE"

    $SCRIPT_DIR/../build/bin/ktest-dehavoc $KTEST $DEHAVOCED_KTEST

    export LD_BIND_NOW=1
    export KTEST_FILE=$DEHAVOCED_KTEST

    pin -t $SCRIPT_DIR/../trace-instructions/pin-trace.so -- \
        ./executable -- --wan 1 --lan-dev 0 \
                    --expire 10 --starting-port 0 --max-flows 65536 || true
    mv trace.out $TRACE
  fi
done
