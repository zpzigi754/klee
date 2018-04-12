#!/bin/bash

set -euo pipefail

UVS="dmap_occupancy Num_bucket_traversals_a Num_bucket_traversals_b Num_hash_collisions_a Num_hash_collisions_b expired_flows"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

function process_uv() {
  UV="$1"

  if [ ! -f "$UV.csv" ]; then
    for VALUE in $(seq 0 8192 65536); do
      echo -n "$VALUE," | tee -a "$UV.csv"
      $SCRIPT_DIR/stitch-traces.sh "$UV=(w32 $VALUE)" | tee -a "$UV.csv"
    done
  fi
}

for UV in $UVS; do
  echo "Processing $UV."
  process_uv "$UV"
done

plot-csv.sh cycles.eps $(echo $UVS | sed -e 's/\([^ ]*\)/\1.csv/g')
