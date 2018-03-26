#!/bin/bash

set -euo pipefail

KLEE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[ -d "$KLEE_DIR/build" ] || mkdir "$KLEE_DIR/build"

cd "$KLEE_DIR/build"

[ -f "Makefile" ] || cmake .. -DGTEST_SRC_DIR=/usr/local/src/libgtest -DENABLE_KLEE_UCLIBC=true -DKLEE_UCLIBC_PATH=/usr/local/src/klee-uclibc -DENABLE_POSIX_RUNTIME=true -DENABLE_UNIT_TESTS=false

make -kj $(nproc)
