#!/bin/bash

set -euo pipefail

TRACE_DIR=${1:-klee-last}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for KTEST in $TRACE_DIR/*.ktest; do
  TRACE="${KTEST%.*}.instructions"

  if [ ! -f "$TRACE" ]; then
    echo "Processing $KTEST -> $TRACE"

    export LD_BIND_NOW=1
    export KTEST_FILE=$KTEST

    pin -t $SCRIPT_DIR/../trace-instructions/pin-trace.so -- \
        ./executable -- --wan 1 --lan-dev 0 \
                    --expire 10 --starting-port 0 --max-flows 65536 || true
    mv trace.out $TRACE
  fi
done
