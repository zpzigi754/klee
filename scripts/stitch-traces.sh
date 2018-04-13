#!/bin/bash

set -euo pipefail

USER_VARS="${1:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$USER_VARS" ]; then
  parallel "echo -n \$(basename {} .call_path)' '; \
            $SCRIPT_DIR/../build/bin/stitch-perf-contract \
                -use-forked-solver=false \
                -contract $SCRIPT_DIR/../../vigor/perf-contracts/perf-contracts.so \
                --user-vars \"$USER_VARS\" \
                {} 2>/dev/null" ::: traces/*.call_path > traces/stateful-perf.txt
else
  parallel "echo -n \$(basename {} .call_path)' '; \
            $SCRIPT_DIR/../build/bin/stitch-perf-contract \
                -use-forked-solver=false \
                -contract $SCRIPT_DIR/../../vigor/perf-contracts/perf-contracts.so \
                {} 2>/dev/null" ::: traces/*.call_path > traces/stateful-perf.txt
fi

awk '
  {
    if ($2 < 0 || totals[$1] < 0) {
      totals[$1] = -1;
    } else {
      totals[$1] += $2;
    }
  }

  END {
    for (trace in totals) {
      print totals[trace];
    }
  }' traces/stateful-perf.txt traces/stateless-perf.txt \
  | sort -n | tail -n 1
