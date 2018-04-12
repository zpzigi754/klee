#!/bin/bash

set -euo pipefail

USER_VARS="$1"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$USER_VARS" ]; then
  parallel "$SCRIPT_DIR/../build/bin/stitch-perf-contract \
                -use-forked-solver=false \
                -contract $SCRIPT_DIR/../../vigor/perf-contracts/perf-contracts.so \
                --user-vars \"$USER_VARS\" \
                {} 2>/dev/null" ::: traces/*.call_path | sort -n | tail -n 1
else
  parallel "$SCRIPT_DIR/../build/bin/stitch-perf-contract \
                -use-forked-solver=false \
                -contract $SCRIPT_DIR/../../vigor/perf-contracts/perf-contracts.so \
                {} 2>/dev/null" ::: traces/*.call_path | sort -n | tail -n 1
fi
