#!/bin/bash

set -euo pipefail

TRACES_DIR=${1:-klee-last}
shift || true

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

function stitch_traces {
  if [ "${1}" ]; then
    eval "declare -A USER_VARS="${1#*=}

    USER_VAR_STR=""
    for VAR in "${!USER_VARS[@]}"; do
      USER_VAR_STR="$USER_VAR_STR,$VAR=(w32 ${USER_VARS[$VAR]})"
    done

    USER_VAR_STR="$(echo "$USER_VAR_STR" | sed -e 's/^,//')"

    parallel "$SCRIPT_DIR/../build/bin/stitch-perf-contract \
                  -contract $SCRIPT_DIR/../../vnds/perf-contracts/perf-contracts.so \
                  --user-vars \"$USER_VAR_STR\" \
                  {} 2>/dev/null \
                | awk \"{ print \\\"\$(basename {} .call_path),\\\" \\\$0; }\"" \
                ::: $TRACES_DIR/*.call_path > $TRACES_DIR/stateful-perf.txt
  else
    parallel "$SCRIPT_DIR/../build/bin/stitch-perf-contract \
                  -contract $SCRIPT_DIR/../../vnds/perf-contracts/perf-contracts.so \
                  {} 2>/dev/null \
                | awk \"{ print \\\"\$(basename {} .call_path),\\\" \\\$0; }\"" \
                ::: $TRACES_DIR/*.call_path > $TRACES_DIR/stateful-perf.txt
  fi

  join -t, -j1 \
      <(sort klee-last/stateful-perf.txt | awk -F, '{print $1 "_" $2 "," $3}') \
      <(sort klee-last/stateless-perf.txt | awk -F, '{print $1 "_" $2 "," $3}') \
    | sed -e 's/_/,/' \
    | awk -F, '
      {
        performance = ($3 + $4);
        if (performance > max_performance[$2]) {
          max_performance[$2] = performance;
        }
      }

      END {
        for (metric in max_performance) {
          print metric "," max_performance[metric];
        }
      }'
}


declare -A USER_VARS=()

while [ "${1:-}" ]; do
  USER_VARS[$1]=$2
  shift 2
done

if [ ${#USER_VARS[@]} -gt 0 ]; then
  BASELINE_PERF=$(stitch_traces "$(declare -p USER_VARS)")

  echo "$BASELINE_PERF"

  for VAR in "${!USER_VARS[@]}"; do
    USER_VARS_STR=$(declare -p USER_VARS)
    eval "declare -A USER_VARS_VARIANT="${USER_VARS_STR#*=}
    USER_VARS_VARIANT["$VAR"]=$((${USER_VARS[$VAR]} + 1))

    VARIANT_PERF=$(stitch_traces "$(declare -p USER_VARS_VARIANT)")
    join -t, -j1 \
        <(echo "$BASELINE_PERF") \
        <(echo "$VARIANT_PERF") \
      | awk -F, "{ print \$1 \",\" (\$3 - \$2) \"/$VAR\"; }"
  done
else
  stitch_traces ""
fi
