// RUN: %llvmgcc %s -emit-llvm -g -c -o %t1.bc
// RUN: rm -rf %t.klee-out
// RUN: %klee --output-dir=%t.klee-out %t1.bc 2>&1 | FileCheck %s

#include <klee/klee.h>
#include <stdio.h>

int main() {
  int x = 3;
  int y = klee_int("y");
  printf("first here\n");
  // CHECK: first here
  klee_forbid_access(&x, sizeof(int), "message");
  for (y = 0; klee_induce_invariants() & y < 10; ++y) {
    klee_allow_access(&x, sizeof(int));
    x = 18;
    klee_forbid_access(&x, sizeof(int), "forbidden in the loop");
  }
  printf("successfully returned\n");
  // CHECK: successfully returned
  return 0;
}
