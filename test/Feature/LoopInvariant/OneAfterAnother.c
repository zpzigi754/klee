// RUN: %llvmgcc %s -emit-llvm -g -c -o %t1.bc
// RUN: rm -rf %t.klee-out
// RUN: %klee --output-dir=%t.klee-out --exit-on-error %t1.bc | FileCheck %s

#include <klee/klee.h>
#include <stdio.h>


int main() {
  int x = 10;
  int y = klee_int("y");
  int z = 0;

  if (5 < y) {
    z = 1;
    printf("taking this one");
    // CHECK: taking this one
  } else {
    z = 2;
    for (int i = 0; i < 10000; ++i);
    printf("taking OTHER one");
  }

  klee_possibly_havoc(&x, sizeof(x), "x");
  klee_possibly_havoc(&y, sizeof(y), "y");
  klee_possibly_havoc(&z, sizeof(z), "z");

  while(klee_induce_invariants() & x--) {
    if (z == 1) {
      printf("z may be 1\n");
      // CHECK: z may be 1
    } else {
      printf("z may be not 1\n");
    }
  }

  if (z == 3) {
    printf("at the end, z may be 3, who knows\n");
    // CHECK-NOT: at the end, z may be 3, who knows
  }

  printf("afterloop\n");
  // CHECK: afterloop
  // CHECK: taking OTHER one
  // CHECK: z may be not 1
  // CHECK: afterloop
  return 0;
}
