// RUN: %llvmgcc %s -emit-llvm -g -c -o %t1.bc
// RUN: rm -rf %t.klee-out
// RUN: %klee --output-dir=%t.klee-out --exit-on-error %t1.bc | FileCheck %s

#include <klee/klee.h>
#include <stdio.h>


int main() {
  int x = 10;
  int y = klee_int("y");
  int z = 0;

  int i = 20;

  klee_possibly_havoc(&x, sizeof(x), "x");
  klee_possibly_havoc(&y, sizeof(y), "y");
  klee_possibly_havoc(&z, sizeof(z), "z");
  klee_possibly_havoc(&i, sizeof(i), "i");

  while (klee_induce_invariants() & i--) {

    while(klee_induce_invariants() & --x) {
      if (z == 1) {
        printf("z may be 1\n");
        // CHECK-NOT: z may be 1
      } else {
        printf("z may be not 1\n");
        // CHECK: z may be not 1
      }
    }
    if (x == -1) printf("x may be -1\n");
    // CHECK-NOT: x may be -1
  }

  printf("\n ----- afterloop ---- \n");
  // CHECK: ----- afterloop ----
  // CHECK-NOT: ----- afterloop ----
  return 0;
}
